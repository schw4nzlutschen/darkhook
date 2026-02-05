#include <darkhook.hpp>

#include <unordered_map>

namespace {
    struct entry {
        void* original;
    };

    std::unordered_map<void*, entry>& storage( ) {
        static std::unordered_map<void*, entry> map;
        return map;
    }
}

extern "C" {
    bool dh_hook_function( void* original, void* target ) {
        if ( !original || !target )
            return false;

        entry e{};
        if ( dh_create_hook( original, target, &e.original ) != DH_OK )
            return false;

        storage( )[ target ] = e;
        return true;
    }

    void* dh_find_original( void* target ) {
        auto& m = storage( );
        const auto it = m.find( target );
        return it == m.end( ) ? nullptr : it->second.original;
    }

    void dh_clear_hooks( void ) {
        storage( ).clear( );
    }
}