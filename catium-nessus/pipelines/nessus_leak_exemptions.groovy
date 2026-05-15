return [
    // This file should contain all trace subsequences that identify leaks we are allowing in Nessus, that we either
    // cannot or will not fix.
    // Here are some examples of how to specify leak exemptions:

    // Allow any leak trace containing a call to funcname() in position 4 (fifth from the lowest)
    // [
    //     sequence: [
    //         [func: 'funcname']
    //     ],
    //     pos: 4
    // ],
    // Allow any leak trace where a call to namespace::funcname() is the code that allocates memory (or at least the
    // lowest function call that is owned by nessusd - any sandwiching calls to functions from other libraries are
    // removed from traces before exemptions are applied)
    // [
    //     sequence: [
    //         [func: 'namespace::funcname']
    //     ],
    //     pos: 0
    // ],
    // Allow any leak trace containing a call at filename.cpp, line 42, anywhere at all in the trace
    // [
    //     sequence: [
    //         [file: 'filename.cpp', line: 42]
    //     ]
    // ],
    // Allow any leak trace containing a call to namespace::Class::funcname() from filename.cpp, line 89, where the call to
    // namespace::funcname() occurs at position 1 or any higher position in the trace
    // [
    //     sequence: [
    //         [func: 'namespace::Class::funcname'],
    //         [file: 'filename.cpp', line: 89]
    //     ],
    //     start: 1
    // ],
    // Allow any leak trace where highfunc() calls into midfunc() at highfile.cpp, line 77, which calls into lowfunc() at
    // midfile.cpp, line 32, which calls into something else at lowfile.cpp, line 6, such that lowfile.cpp:6 is at
    // position 2 or 3, midfile.cpp:32 is at position 3 or 4, and highfile.cpp:77 is at position 4 or 5. All three items
    // must be present and all three values of func, file, and line must match for a trace to be exempted.
    //[
    //    sequence: [
    //        [func: 'lowfunc', file: 'lowfile.cpp', line: 6],
    //        [func: 'midfunc', file: 'midfile.cpp', line: 32],
    //        [func: 'highfunc', file: 'highfile.cpp', line: 77]
    //    ],
    //    start: 2,
    //    end: 3
    //]
]