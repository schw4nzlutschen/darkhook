#pragma once
#include <darkhook.h>

#ifdef __cplusplus
extern "C" {
#endif
    bool dh_hook_function( void* original, void* target );
    void* dh_find_original( void* target );
    void dh_clear_hooks( void );

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
namespace darkhook {
    inline bool hook_function( void* original, void* target ) noexcept {
        return dh_hook_function( original, target );
    }

    template<typename Fn>
    [[nodiscard]] inline Fn find_original( Fn target ) noexcept {
        return reinterpret_cast<Fn>( dh_find_original( reinterpret_cast<void*>( target ) ) );
    }

    inline void clear_hooks( ) noexcept {
        dh_clear_hooks( );
    }

} // namespace darkhook
#endif