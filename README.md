# DarkHook

Minimalistic x86/x64 API hooking library for Windows, built on top of MinHook.

DarkHook preserves the original MinHook core while exposing a **modern C++23 API**
with a safe, clean, and consistent `snake_case` interface.

---

## ✨ Features

- x86 / x64 support
- Windows-only
- Built on top of the proven MinHook core
- Modern C++23 API
- Header-only public interface
- Simple global hook registry
- Pattern & vtable helpers
- CMake-friendly (FetchContent)

---

## 📦 Installation (CMake)

DarkHook is designed to be consumed via **CMake FetchContent**, similar to
[SafetyHook](https://github.com/cursey/safetyhook).

### Example

```cmake
include(FetchContent)

FetchContent_Declare(
    darkhook
    GIT_REPOSITORY https://github.com/schw4nzlutschen/darkhook.git
    GIT_TAG origin/main
)

FetchContent_MakeAvailable(darkhook)

target_link_libraries(${PROJECT_NAME} PRIVATE darkhook)
```

That’s it — no additional setup required.

---

## 📚 Usage

Include the main header:

```cpp
#include <darkhook.hpp>
```

### Basic Hook Example

```cpp
#include <darkhook.hpp>

using namespace darkhook;

// Hooked function
void __fastcall example_func(void* a1, int a2) {
    static auto original = find_original(&example_func);
    original(a1, a2);

    // Your custom logic here
}

void initialize() {
    dh_initialize();

    hook_function(vtable::get(your_class, 1), &example_func);
    hook_function(patterns.your_pattern.as<void*>(), &your_func);

    dh_enable_hook(DH_ALL_HOOKS);
}

void destroy() {
    dh_disable_hook(DH_ALL_HOOKS);

    clear_hooks();
    
    dh_uninitialize();
}
```

---

## 🧠 API Overview

### Initialization

```cpp
dh_initialize();
dh_uninitialize();
```

Initializes and shuts down the DarkHook system.

---

### Hook Control

```cpp
dh_enable_hook(DH_ALL_HOOKS);
dh_disable_hook(DH_ALL_HOOKS);
```

Enables or disables all registered hooks.

---

### Hook Registration

```cpp
hook_function(void* target, void* detour);
clear_hooks();
```

Registers hooks and clears the internal hook registry.

---

### Original Function Access

```cpp
auto original = find_original(&your_hook);
```

Retrieves the original function pointer associated with a hook.

---

## ⚠️ Notes

- Thread-safety follows MinHook guarantees
- Hooks should be enabled only after successful initialization
- Intended for low-level / internal tooling, not sandboxed environments

---

## 📜 License

This project is licensed under the **MIT License**.

MinHook is licensed under the **BSD 2-Clause License**  
Original MinHook repository: https://github.com/TsudaKageyu/minhook

---

## ❤️ Credits

- TsudaKageyu — MinHook
- cursey — SafetyHook inspiration
