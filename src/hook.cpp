/*
LOCKING INVARIANTS

g_hooks_lock:
  - Protects g_hooks, hook_entry, flags, trampolines
  - Must NOT be held while threads are suspended

g_freeze_lock:
  - Serializes freeze_threads / unfreeze_threads
  - Ensures only one freeze operation at a time

Rules:
  - Never hold g_hooks_lock while calling freeze_threads
  - Never attempt SRWLOCK upgrade (Shared -> Exclusive)
  - freeze_threads must always be paired with unfreeze_threads

ADDITIONAL INVARIANT

While g_freeze_lock is held:
  - g_hooks structure and hook_entry contents MUST NOT be modified
  - g_hooks_lock may be temporarily acquired inside freeze window
*/

#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>
#include <cstdint>

#include "../include/darkhook.h"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

 // Initial capacity of the hook_entry buffer.
#define INITIAL_HOOK_CAPACITY   32

// Initial capacity of the thread IDs buffer.
#define INITIAL_THREAD_CAPACITY 128

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// freeze_threads() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Thread access rights for suspending/resuming threads.
#define THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

#define HOOK_PATCH_ABOVE  0x01      // Uses the hot patch area.
#define HOOK_ENABLED      0x02      // Enabled.
#define HOOK_QUEUE_ENABLE 0x04      // Queued for enabling/disabling when != is_enabled.

// Hook lifecycle state.
enum class _hook_state : uint8_t {
    empty,      // The object is created, but the hook is not initialized
    prepared,   // Trampoline + analysis ready
    enabled,    // The code is patched
    disabled,   // The patch has been removed, but trampoline is still alive.
    destroyed   // Everything is freed
};

// Hook information.
typedef struct _hook_entry
{
    LPVOID target;             // Address of the target function.
    LPVOID detour;             // Address of the detour or relay function.
    LPVOID trampoline;         // Address of the trampoline function.

	_hook_state state;         // Lifecycle state of the hook.

    // size backup to the maximum patch we may write/restore.
    // we may restore either:
    // - sizeof(jmp_rel)                         (normal)
    // - sizeof(jmp_rel) + sizeof(jmp_rel_short) (patch_above)
    UINT8  backup[ sizeof( jmp_rel ) + sizeof( jmp_rel_short ) ];     // Original prologue of the target function.

    UINT8 flags;

    UINT8 instruction_count;       // Count of the instruction boundaries.
    UINT8  old_ips[ 8 ];           // Instruction boundaries of the target function.
    UINT8  new_ips[ 8 ];           // Instruction boundaries of the trampoline function.
} hook_entry, *phook_entry;

// Suspended threads for freeze_threads()/unfreeze_threads().
typedef struct _frozen_threads
{
    LPDWORD items;          // Data heap
    UINT    capacity;       // Size of allocated data heap, items
    UINT    size;           // Actual number of data items
} frozen_threads, * pfrozen_threads;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Protects g_hooks, flags, trampolines
static SRWLOCK g_hooks_lock = SRWLOCK_INIT;

// Protects freeze/unfreeze phase
static SRWLOCK g_freeze_lock = SRWLOCK_INIT;

// Private heap handle. If not NULL, this library is initialized.
static HANDLE g_h_heap = NULL;

// Hook entries.
static struct
{
    phook_entry items;      // Data heap
    UINT        capacity;   // Size of allocated data heap, items
    UINT        size;       // Actual number of data items
} g_hooks;

static __forceinline BOOL hook_is_enabled( phook_entry h )
{
    return ( h->flags & HOOK_ENABLED ) != 0;
}

static __forceinline BOOL hook_is_queued( phook_entry h )
{
    return ( h->flags & HOOK_QUEUE_ENABLE ) != 0;
}

static __forceinline VOID set_hook_flags( phook_entry h, BOOL enable )
{
    if ( enable ) {
        h->flags |= HOOK_ENABLED | HOOK_QUEUE_ENABLE;
    }
    else {
        h->flags &= ~( HOOK_ENABLED | HOOK_QUEUE_ENABLE );
    }
}

// Checks if a state transition is valid. This is used to enforce the correct lifecycle of hooks.
static bool is_transition_allowed( _hook_state from, _hook_state to ) {
    switch ( from ) {
    case _hook_state::empty:
        return to == _hook_state::prepared;

    case _hook_state::prepared:
        return to == _hook_state::enabled || to == _hook_state::destroyed;

    case _hook_state::enabled:
        return to == _hook_state::disabled;

    case _hook_state::disabled:
        return to == _hook_state::enabled || to == _hook_state::destroyed;

    default:
        return false;
    }
}

// Performs a state transition if allowed. Returns true if the transition was successful, false otherwise.
static bool transition( hook_entry* h, _hook_state to ) 
{
    if ( !is_transition_allowed( h->state, to ) )
        return false;

    h->state = to;
    return true;
}

// Returns INVALID_HOOK_POS if not found.
static UINT find_hook_entry( LPVOID target )
{
    UINT i;
    for ( i = 0; i < g_hooks.size; ++i )
    {
        if ( (ULONG_PTR)target == (ULONG_PTR)g_hooks.items[ i ].target )
            return i;
    }

    return INVALID_HOOK_POS;
}

static phook_entry add_hook_entry( )
{
    if ( g_hooks.items == NULL )
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.items = (phook_entry)HeapAlloc(
            g_h_heap, 0, g_hooks.capacity * sizeof( hook_entry ) );
        if ( g_hooks.items == NULL )
            return NULL;
    }
    else if ( g_hooks.size >= g_hooks.capacity )
    {
        phook_entry p = (phook_entry)HeapReAlloc(
            g_h_heap, 0, g_hooks.items, ( g_hooks.capacity * 2 ) * sizeof( hook_entry ) );
        if ( p == NULL )
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.items = p;
    }

    return &g_hooks.items[ g_hooks.size++ ];
}

static VOID delete_hook_entry( UINT pos )
{
    if ( pos >= g_hooks.size )
        return;

    for ( UINT i = pos + 1; i < g_hooks.size; ++i )
    {
        g_hooks.items[ i - 1 ] = g_hooks.items[ i ];
    }

    g_hooks.size--;

    if ( g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY &&
        g_hooks.capacity / 2 >= g_hooks.size )
    {
        phook_entry p = (phook_entry)HeapReAlloc(
            g_h_heap, 0,
            g_hooks.items,
            ( g_hooks.capacity / 2 ) * sizeof( hook_entry ) );

        if ( p != NULL )
        {
            g_hooks.capacity /= 2;
            g_hooks.items = p;
        }
    }
}

static DWORD_PTR find_old_ip( phook_entry hook, DWORD_PTR ip )
{
    UINT i;

    if ( ( hook->flags & HOOK_PATCH_ABOVE ) && ip == ( (DWORD_PTR)hook->target - sizeof( jmp_rel ) ) )
        return (DWORD_PTR)hook->target;

    for ( i = 0; i < hook->instruction_count; ++i )
    {
        if ( ip == ( (DWORD_PTR)hook->trampoline + hook->new_ips[ i ] ) )
            return (DWORD_PTR)hook->target + hook->old_ips[ i ];
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Check relay function.
    if ( ip == (DWORD_PTR)hook->detour )
        return (DWORD_PTR)hook->target;
#endif

    return 0;
}

static DWORD_PTR find_new_ip( phook_entry hook, DWORD_PTR ip )
{
    UINT i;
    for ( i = 0; i < hook->instruction_count; ++i )
    {
        if ( ip == ( (DWORD_PTR)hook->target + hook->old_ips[ i ] ) )
            return (DWORD_PTR)hook->trampoline + hook->new_ips[ i ];
    }

    return 0;
}

/*
process_thread_ips:
  - Called ONLY while g_freeze_lock is held
  - Safe to read g_hooks without g_hooks_lock
*/
/*
process_thread_ips:
  - Called ONLY while g_freeze_lock is held
  - g_hooks MUST NOT be modified during this window
*/
static VOID process_thread_ips( HANDLE thread_handle, UINT pos, UINT action )
{
    CONTEXT ctx{};
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64* ip = &ctx.Rip;
#else
    DWORD* ip = &ctx.Eip;
#endif

    ctx.ContextFlags = CONTEXT_CONTROL;
    if ( !GetThreadContext( thread_handle, &ctx ) )
        return;

    UINT begin = ( pos == ALL_HOOKS_POS ) ? 0 : pos;
    UINT end = ( pos == ALL_HOOKS_POS ) ? g_hooks.size : pos + 1;

    for ( UINT i = begin; i < end; ++i )
    {
        phook_entry h = &g_hooks.items[ i ];

        BOOL target_enabled;
        switch ( action )
        {
        case ACTION_ENABLE:       target_enabled = TRUE; break;
        case ACTION_DISABLE:      target_enabled = FALSE; break;
        default:                  target_enabled = hook_is_queued( h ); break;
        }

        if ( hook_is_enabled( h ) == target_enabled )
            continue;

        DWORD_PTR new_ip = target_enabled
            ? find_new_ip( h, *ip )
            : find_old_ip( h, *ip );

        if ( new_ip )
        {
            *ip = new_ip;
            SetThreadContext( thread_handle, &ctx );
        }
    }
}

static BOOL enumerate_threads( pfrozen_threads threads )
{
    // make enumerate_threads self-contained/safe to call.
    threads->items = NULL;
    threads->capacity = 0;
    threads->size = 0;

    BOOL succeeded = FALSE;

    HANDLE snapshot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( snapshot_handle != INVALID_HANDLE_VALUE )
    {
        THREADENTRY32 te;
        te.dwSize = sizeof( THREADENTRY32 );
        if ( Thread32First( snapshot_handle, &te ) )
        {
            succeeded = TRUE;
            do
            {
                if ( te.dwSize >= ( FIELD_OFFSET( THREADENTRY32, th32OwnerProcessID ) + sizeof( DWORD ) )
                    && te.th32OwnerProcessID == GetCurrentProcessId( )
                    && te.th32ThreadID != GetCurrentThreadId( ) )
                {
                    if ( threads->items == NULL )
                    {
                        threads->capacity = INITIAL_THREAD_CAPACITY;
                        threads->items
                            = (LPDWORD)HeapAlloc( g_h_heap, 0, threads->capacity * sizeof( DWORD ) );
                        if ( threads->items == NULL )
                        {
                            succeeded = FALSE;
                            break;
                        }
                    }
                    else if ( threads->size >= threads->capacity )
                    {
                        LPDWORD p;
                        threads->capacity *= 2;
                        p = (LPDWORD)HeapReAlloc(
                            g_h_heap, 0, threads->items, threads->capacity * sizeof( DWORD ) );
                        if ( p == NULL )
                        {
                            succeeded = FALSE;
                            break;
                        }

                        threads->items = p;
                    }
                    threads->items[ threads->size++ ] = te.th32ThreadID;
                }

                te.dwSize = sizeof( THREADENTRY32 );
            } while ( Thread32Next( snapshot_handle, &te ) );

            if ( succeeded && GetLastError( ) != ERROR_NO_MORE_FILES )
                succeeded = FALSE;

            if ( !succeeded && threads->items != NULL )
            {
                HeapFree( g_h_heap, 0, threads->items );
                threads->items = NULL;
            }
        }
        CloseHandle( snapshot_handle );
    }

    return succeeded;
}

/*
freeze_threads:
  - Must be called under g_freeze_lock
  - Must NOT be called under g_hooks_lock
*/
static dh_status freeze_threads( pfrozen_threads threads, UINT pos, UINT action )
{
    if ( g_h_heap == NULL )
        return DH_ERROR_NOT_INITIALIZED;

    dh_status status = DH_OK;

    threads->items = NULL;
    threads->capacity = 0;
    threads->size = 0;

    // We iterate until no new threads appear
    for ( ;; )
    {
        frozen_threads round = { 0 };

        if ( !enumerate_threads( &round ) )
        {
            status = DH_ERROR_MEMORY_ALLOC;
            break;
        }

        BOOL any_new = FALSE;

        for ( UINT i = 0; i < round.size; ++i )
        {
            DWORD tid = round.items[ i ];

            // Check if this thread was already frozen
            BOOL already = FALSE;
            for ( UINT j = 0; j < threads->size; ++j )
            {
                if ( threads->items[ j ] == tid )
                {
                    already = TRUE;
                    break;
                }
            }

            if ( already )
                continue;

            HANDLE thread_handle = OpenThread( THREAD_ACCESS, FALSE, tid );
            BOOL suspended = FALSE;

            if ( thread_handle != NULL )
            {
                DWORD result = SuspendThread( thread_handle );
                if ( result != (DWORD)-1 )
                {
                    suspended = TRUE;
                    process_thread_ips( thread_handle, pos, action );
                }
                CloseHandle( thread_handle );
            }

            if ( suspended )
            {
                // append to frozen list
                if ( threads->items == NULL )
                {
                    threads->capacity = INITIAL_THREAD_CAPACITY;
                    threads->items = (LPDWORD)HeapAlloc(
                        g_h_heap, 0, threads->capacity * sizeof( DWORD ) );
                    if ( threads->items == NULL )
                    {
                        status = DH_ERROR_MEMORY_ALLOC;
                        break;
                    }
                }
                else if ( threads->size >= threads->capacity )
                {
                    threads->capacity *= 2;
                    LPDWORD p = (LPDWORD)HeapReAlloc(
                        g_h_heap, 0, threads->items,
                        threads->capacity * sizeof( DWORD ) );
                    if ( p == NULL )
                    {
                        status = DH_ERROR_MEMORY_ALLOC;
                        break;
                    }
                    threads->items = p;
                }

                threads->items[ threads->size++ ] = tid;
                any_new = TRUE;
            }
        }

        if ( round.items )
            HeapFree( g_h_heap, 0, round.items );

        if ( status != DH_OK )
            break;

        // no new threads => stable snapshot
        if ( !any_new )
            break;
    }

    return status;
}

static VOID unfreeze_threads( pfrozen_threads threads )
{
    if ( threads->items != NULL )
    {
        UINT i;
        for ( i = 0; i < threads->size; ++i )
        {
            DWORD thread_id = threads->items[ i ];
            if ( thread_id != 0 )
            {
                HANDLE thread_handle = OpenThread( THREAD_ACCESS, FALSE, thread_id );
                if ( thread_handle != NULL )
                {
                    ResumeThread( thread_handle );
                    CloseHandle( thread_handle );
                }
            }
        }

        HeapFree( g_h_heap, 0, threads->items );
        threads->items = NULL;
        threads->size = 0;
        threads->capacity = 0;
    }
}

// Patch ONLY executable memory.
// Caller must hold g_hooks_lock.
// MUST NOT touch hook->flags.
static dh_status patch_hook_code_only( UINT pos, BOOL enable )
{
    phook_entry h = &g_hooks.items[ pos ];

    SIZE_T patch_size = sizeof( jmp_rel );
    LPBYTE patch_addr = (LPBYTE)h->target;

    if ( h->flags & HOOK_PATCH_ABOVE )
    {
        patch_addr -= sizeof( jmp_rel );
        patch_size += sizeof( jmp_rel_short );
    }

    DWORD old_protect;
    if ( !VirtualProtect( patch_addr, patch_size, PAGE_EXECUTE_READWRITE, &old_protect ) )
        return DH_ERROR_MEMORY_PROTECT;

    if ( enable )
    {
        pjmp_rel j = (pjmp_rel)patch_addr;
        j->opcode = 0xE9;
        j->operand = (INT32)(
            (LPBYTE)h->detour - ( patch_addr + sizeof( jmp_rel ) )
            );

        if ( h->flags & HOOK_PATCH_ABOVE )
        {
            pjmp_rel_short sj = (pjmp_rel_short)h->target;
            sj->opcode = 0xEB;
            sj->operand = (INT8)(
                0 - ( sizeof( jmp_rel ) + sizeof( jmp_rel_short ) )
                );
        }
    }
    else
    {
        memcpy( patch_addr, h->backup, patch_size );
    }

    FlushInstructionCache( GetCurrentProcess( ), patch_addr, patch_size );
    VirtualProtect( patch_addr, patch_size, old_protect, &old_protect );

    return DH_OK;
}

/*
enable_all_hooks_frozen:

REQUIRES:
  - g_hooks_lock is NOT held by caller

BEHAVIOR:
  - Acquires g_freeze_lock
  - Freezes threads
  - Acquires g_hooks_lock internally
*/
static dh_status enable_all_hooks_frozen( BOOL enable )
{
    // PHASE 1 (freeze):
    //   - threads suspended
    //   - ONLY executable memory is patched
    //   - hook flags MUST NOT be modified
    //
    // PHASE 2 (commit):
    //   - threads resumed
    //   - hook flags are updated

    frozen_threads threads{};
    dh_status status = DH_OK;

    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    UINT count = g_hooks.size;

    for ( UINT i = 0; i < count; ++i )
    {
        if ( !is_transition_allowed( g_hooks.items[ i ].state, enable ? _hook_state::enabled : _hook_state::disabled ) )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_INVALID_STATE;
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    AcquireSRWLockExclusive( &g_freeze_lock );

    status = freeze_threads(
        &threads,
        ALL_HOOKS_POS,
        enable ? ACTION_ENABLE : ACTION_DISABLE
    );

    if ( status != DH_OK )
    {
        ReleaseSRWLockExclusive( &g_freeze_lock );
        return status;
    }

    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_hooks.size != count )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        unfreeze_threads( &threads );
        ReleaseSRWLockExclusive( &g_freeze_lock );
        return DH_ERROR_INVALID_STATE;
    }

    for ( UINT i = 0; i < count; ++i )
    {
        if ( hook_is_enabled( &g_hooks.items[ i ] ) != enable )
        {
            status = patch_hook_code_only( i, enable );
            if ( status != DH_OK )
                break;
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    unfreeze_threads( &threads );
    ReleaseSRWLockExclusive( &g_freeze_lock );

    if ( status != DH_OK )
        return status;

    AcquireSRWLockExclusive( &g_hooks_lock );

    for ( UINT i = 0; i < count; ++i )
    {
        if ( hook_is_enabled( &g_hooks.items[ i ] ) != enable )
        {
            if ( !transition( &g_hooks.items[ i ], enable ? _hook_state::enabled : _hook_state::disabled ) )
            {
                ReleaseSRWLockExclusive( &g_hooks_lock );
                return DH_ERROR_INVALID_STATE;
            }

            set_hook_flags( &g_hooks.items[ i ], enable );
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );
    return DH_OK;
}

dh_status WINAPI dh_initialize( VOID )
{
    dh_status status = DH_OK;

    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        g_h_heap = HeapCreate( 0, 0, 0 );
        if ( g_h_heap != NULL )
        {
            // Initialize the internal function buffer.
            initialize_buffer( );
        }
        else
        {
            status = DH_ERROR_MEMORY_ALLOC;
        }
    }
    else
    {
        status = DH_ERROR_ALREADY_INITIALIZED;
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    return status;
}

dh_status WINAPI dh_uninitialize( VOID )
{
    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    // disable hooks OUTSIDE hooks lock
    dh_status status = enable_all_hooks_frozen( FALSE );
    if ( status != DH_OK )
        return status;

    // now destroy under hooks lock
    AcquireSRWLockExclusive( &g_hooks_lock );

	// Ensure all hooks are disabled before uninitialization.
    for ( UINT i = 0; i < g_hooks.size; ++i )
    {
        if ( g_hooks.items[ i ].state == _hook_state::enabled )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_INVALID_STATE;
        }
    }

    uninitialize_buffer( );
    HeapFree( g_h_heap, 0, g_hooks.items );
    HeapDestroy( g_h_heap );

    g_h_heap = NULL;
    g_hooks.items = NULL;
    g_hooks.capacity = 0;
    g_hooks.size = 0;

    ReleaseSRWLockExclusive( &g_hooks_lock );
    return DH_OK;
}

dh_status WINAPI dh_create_hook( LPVOID target, LPVOID detour, LPVOID* original )
{
    dh_status status = DH_OK;

    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    if ( !is_executable_address( target ) || !is_executable_address( detour ) )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_EXECUTABLE;
    }

    if ( find_hook_entry( target ) != INVALID_HOOK_POS )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_ALREADY_CREATED;
    }

    LPVOID buffer = allocate_buffer( target );
    if ( buffer == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_MEMORY_ALLOC;
    }

    trampoline trampoline_data;
    trampoline_data.target = target;
    trampoline_data.detour = detour;
    trampoline_data.trampoline = buffer;

    if ( !create_trampoline_function( &trampoline_data ) )
    {
        free_buffer( buffer );
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_UNSUPPORTED_FUNCTION;
    }

    phook_entry hook = add_hook_entry( );
    if ( hook == NULL )
    {
        free_buffer( buffer );
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_MEMORY_ALLOC;
    }

    hook->state = _hook_state::empty;

    hook->target = trampoline_data.target;

#if defined(_M_X64) || defined(__x86_64__)
    hook->detour = trampoline_data.relay;
#else
    hook->detour = trampoline_data.detour;
#endif

    hook->trampoline = trampoline_data.trampoline;

    hook->flags = 0;
    if ( trampoline_data.patch_above )
        hook->flags |= HOOK_PATCH_ABOVE;

    hook->instruction_count = trampoline_data.instruction_count;
    memcpy( hook->old_ips, trampoline_data.old_ips, ARRAYSIZE( trampoline_data.old_ips ) );
    memcpy( hook->new_ips, trampoline_data.new_ips, ARRAYSIZE( trampoline_data.new_ips ) );

    if ( trampoline_data.patch_above )
    {
        memcpy(
            hook->backup,
            (LPBYTE)target - sizeof( jmp_rel ),
            sizeof( jmp_rel ) + sizeof( jmp_rel_short )
        );
    }
    else
    {
        memcpy( hook->backup, target, sizeof( jmp_rel ) );
    }

    if ( original != NULL )
        *original = hook->trampoline;

    if ( !transition( hook, _hook_state::prepared ) )
    {
		// This should never happen, but if it does, we need to clean up the allocated resources.
        free_buffer( hook->trampoline );
        delete_hook_entry( g_hooks.size - 1 );
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_INVALID_STATE;
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );
    return DH_OK;
}

dh_status WINAPI dh_remove_hook( LPVOID target )
{
    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    UINT pos = find_hook_entry( target );
    if ( pos == INVALID_HOOK_POS )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_CREATED;
    }

    phook_entry h = &g_hooks.items[ pos ];

    if ( hook_is_enabled( h ) )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_INVALID_STATE;
    }

    if ( h->state != _hook_state::prepared &&
        h->state != _hook_state::disabled )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_INVALID_STATE;
    }

    transition( h, _hook_state::destroyed );

    free_buffer( h->trampoline );
    delete_hook_entry( pos );

    ReleaseSRWLockExclusive( &g_hooks_lock );
    return DH_OK;
}


static dh_status enable_hook( LPVOID target, BOOL enable )
{
    dh_status status;
    BOOL enabled_snapshot;

    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    UINT pos = find_hook_entry( target );
    if ( pos == INVALID_HOOK_POS )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_CREATED;
    }

    phook_entry h = &g_hooks.items[ pos ];

    if ( enable )
    {
        if ( !is_transition_allowed( h->state, _hook_state::enabled ) )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_INVALID_STATE;
        }
    }
    else
    {
        if ( !is_transition_allowed( h->state, _hook_state::disabled ) )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_INVALID_STATE;
        }
    }

    enabled_snapshot = hook_is_enabled( &g_hooks.items[ pos ] );
    ReleaseSRWLockExclusive( &g_hooks_lock );

    if ( enabled_snapshot == enable )
        return enable ? DH_ERROR_ENABLED : DH_ERROR_DISABLED;

    frozen_threads threads;

    AcquireSRWLockExclusive( &g_freeze_lock );
    status = freeze_threads(
        &threads,
        pos,
        enable ? ACTION_ENABLE : ACTION_DISABLE
    );
    ReleaseSRWLockExclusive( &g_freeze_lock );

    if ( status != DH_OK )
        return status;

    AcquireSRWLockExclusive( &g_hooks_lock );

    pos = find_hook_entry( target );
    if ( pos == INVALID_HOOK_POS )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        unfreeze_threads( &threads );
        return DH_ERROR_NOT_CREATED;
    }

    status = patch_hook_code_only( pos, enable );
    ReleaseSRWLockExclusive( &g_hooks_lock );

    unfreeze_threads( &threads );

    if ( status != DH_OK )
        return status;

    AcquireSRWLockExclusive( &g_hooks_lock );

    pos = find_hook_entry( target );
    if ( pos != INVALID_HOOK_POS )
    {
        if ( !transition( &g_hooks.items[ pos ], enable ? _hook_state::enabled : _hook_state::disabled ) )
        {
			// This should never happen, but if it does, we need to clean up the allocated resources.
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_INVALID_STATE;
        }

		set_hook_flags( &g_hooks.items[ pos ], enable );
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );
    return DH_OK;
}

dh_status WINAPI dh_enable_hook( LPVOID target )
{
    if ( target == DH_ALL_HOOKS )
        return enable_all_hooks_frozen( TRUE );

    return enable_hook( target, TRUE );
}

dh_status WINAPI dh_disable_hook( LPVOID target )
{
    if ( target == DH_ALL_HOOKS )
        return enable_all_hooks_frozen( FALSE );

    return enable_hook( target, FALSE );
}

static dh_status queue_hook( LPVOID target, BOOL queue_enable )
{
    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    UINT begin, end;

    if ( target == DH_ALL_HOOKS )
    {
        begin = 0;
        end = g_hooks.size;
    }
    else
    {
        begin = find_hook_entry( target );
        if ( begin == INVALID_HOOK_POS )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_NOT_CREATED;
        }
        end = begin + 1;
    }

    for ( UINT i = begin; i < end; ++i )
    {
        phook_entry h = &g_hooks.items[ i ];

        if ( !is_transition_allowed( h->state, queue_enable ? _hook_state::enabled : _hook_state::disabled ) )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            return DH_ERROR_INVALID_STATE;
        }

        if ( queue_enable )
            h->flags |= HOOK_QUEUE_ENABLE;
        else
            h->flags &= ~HOOK_QUEUE_ENABLE;
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );
    return DH_OK;
}


dh_status WINAPI dh_queue_enable_hook( LPVOID target )
{
    return queue_hook( target, TRUE );
}

dh_status WINAPI dh_queue_disable_hook( LPVOID target )
{
    return queue_hook( target, FALSE );
}

dh_status WINAPI dh_apply_queued( VOID )
{
    dh_status status = DH_OK;
    frozen_threads threads{};

    _hook_state* state_snapshot = nullptr;
    UINT count = 0;

	// phase 0: validate that all queued state changes are valid and take a snapshot of current states.
    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_h_heap == NULL )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_NOT_INITIALIZED;
    }

    count = g_hooks.size;

    state_snapshot = (_hook_state*)HeapAlloc(
        g_h_heap, 0, count * sizeof( _hook_state )
    );

    if ( !state_snapshot )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        return DH_ERROR_MEMORY_ALLOC;
    }

    BOOL need_apply = FALSE;

    for ( UINT i = 0; i < count; ++i )
    {
        phook_entry h = &g_hooks.items[ i ];
        state_snapshot[ i ] = h->state;

        BOOL target = hook_is_queued( h );

        if ( hook_is_enabled( h ) != target )
        {
            if ( !is_transition_allowed(
                h->state,
                target ? _hook_state::enabled : _hook_state::disabled ) )
            {
                HeapFree( g_h_heap, 0, state_snapshot );
                ReleaseSRWLockExclusive( &g_hooks_lock );
                return DH_ERROR_INVALID_STATE;
            }
            need_apply = TRUE;
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    if ( !need_apply )
    {
        HeapFree( g_h_heap, 0, state_snapshot );
        return DH_OK;
    }

	// phase 1: freeze threads and apply code patches WITHOUT committing state changes (flags)
    AcquireSRWLockExclusive( &g_freeze_lock );

    status = freeze_threads(
        &threads,
        ALL_HOOKS_POS,
        ACTION_APPLY_QUEUED
    );

    if ( status != DH_OK )
    {
        ReleaseSRWLockExclusive( &g_freeze_lock );
        HeapFree( g_h_heap, 0, state_snapshot );
        return status;
    }

	// phase 1.5: validate that state didn't change during freeze (should never happen)
    AcquireSRWLockExclusive( &g_hooks_lock );

    if ( g_hooks.size != count )
    {
        ReleaseSRWLockExclusive( &g_hooks_lock );
        unfreeze_threads( &threads );
        ReleaseSRWLockExclusive( &g_freeze_lock );
        HeapFree( g_h_heap, 0, state_snapshot );
        return DH_ERROR_INVALID_STATE;
    }

    for ( UINT i = 0; i < count; ++i )
    {
        if ( g_hooks.items[ i ].state != state_snapshot[ i ] )
        {
            ReleaseSRWLockExclusive( &g_hooks_lock );
            unfreeze_threads( &threads );
            ReleaseSRWLockExclusive( &g_freeze_lock );
            HeapFree( g_h_heap, 0, state_snapshot );
            return DH_ERROR_INVALID_STATE;
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

	// phase 2: apply code patches
    AcquireSRWLockExclusive( &g_hooks_lock );

    for ( UINT i = 0; i < count; ++i )
    {
        phook_entry h = &g_hooks.items[ i ];
        BOOL target = hook_is_queued( h );

        if ( hook_is_enabled( h ) != target )
        {
            status = patch_hook_code_only( i, target );
            if ( status != DH_OK )
                break;
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    unfreeze_threads( &threads );
    ReleaseSRWLockExclusive( &g_freeze_lock );

    if ( status != DH_OK )
    {
        HeapFree( g_h_heap, 0, state_snapshot );
        return status;
    }

	// Phase 3: commit
    AcquireSRWLockExclusive( &g_hooks_lock );

    for ( UINT i = 0; i < count; ++i )
    {
        phook_entry h = &g_hooks.items[ i ];
        BOOL target = hook_is_queued( h );

        if ( hook_is_enabled( h ) != target )
        {
            if ( !transition( h, target ? _hook_state::enabled : _hook_state::disabled ) )
            {
                ReleaseSRWLockExclusive( &g_hooks_lock );
                HeapFree( g_h_heap, 0, state_snapshot );
                return DH_ERROR_INVALID_STATE;
            }

            set_hook_flags( h, target );
        }
    }

    ReleaseSRWLockExclusive( &g_hooks_lock );

    HeapFree( g_h_heap, 0, state_snapshot );
    return DH_OK;
}


dh_status WINAPI dh_create_hook_api_ex(
    LPCWSTR module_name, LPCSTR proc_name, LPVOID detour,
    LPVOID* original, LPVOID* target_out )
{
    HMODULE module_handle;
    LPVOID  target;

    module_handle = GetModuleHandleW( module_name );
    if ( module_handle == NULL )
        return DH_ERROR_MODULE_NOT_FOUND;

    target = (LPVOID)GetProcAddress( module_handle, proc_name );
    if ( target == NULL )
        return DH_ERROR_FUNCTION_NOT_FOUND;

    if ( target_out != NULL )
        *target_out = target;

    return dh_create_hook( target, detour, original );
}

dh_status WINAPI dh_create_hook_api(
    LPCWSTR module_name, LPCSTR proc_name, LPVOID detour, LPVOID* original )
{
    return dh_create_hook_api_ex( module_name, proc_name, detour, original, NULL );
}

const char* WINAPI dh_status_to_string( dh_status status )
{
#define DH_ST2STR(x)    \
    case x:             \
        return #x;

    switch ( status ) {
        DH_ST2STR( DH_UNKNOWN )
            DH_ST2STR( DH_OK )
            DH_ST2STR( DH_ERROR_ALREADY_INITIALIZED )
            DH_ST2STR( DH_ERROR_NOT_INITIALIZED )
            DH_ST2STR( DH_ERROR_ALREADY_CREATED )
            DH_ST2STR( DH_ERROR_NOT_CREATED )
            DH_ST2STR( DH_ERROR_ENABLED )
            DH_ST2STR( DH_ERROR_DISABLED )
            DH_ST2STR( DH_ERROR_NOT_EXECUTABLE )
            DH_ST2STR( DH_ERROR_UNSUPPORTED_FUNCTION )
            DH_ST2STR( DH_ERROR_MEMORY_ALLOC )
            DH_ST2STR( DH_ERROR_MEMORY_PROTECT )
            DH_ST2STR( DH_ERROR_MODULE_NOT_FOUND )
            DH_ST2STR( DH_ERROR_FUNCTION_NOT_FOUND )
    }

#undef DH_ST2STR

    return "(unknown)";
}