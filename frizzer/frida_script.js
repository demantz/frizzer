"use strict"
var debugging_enabled = false
function debug(msg)   { if(debugging_enabled){console.log("[+ ("+Process.id+")] " + msg)} }
function debugCov(msg){ if(debugging_enabled){console.log("[+ ("+Process.id+")] " + msg)} }
function warning(msg) { console.warn("[!] " + msg) }

debug("loading script...")

var stalker_attached = false;
var stalker_finished = false;

var whitelist = ['all'];

var gc_cnt = 0;

function make_maps() {
    var maps = Process.enumerateModulesSync();
    var i = 0;
    // We need to add the module id
    maps.map(function(o) { o.id = i++; });
    // .. and the module end point
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;
}
var maps = make_maps()

// We want to use frida's ModuleMap to create DRcov events, however frida's
//  Module object doesn't have the 'id' we added above. To get around this,
//  we'll create a mapping from path -> id, and have the ModuleMap look up the
//  path. While the ModuleMap does contain the base address, if we cache it
//  here, we can simply look up the path rather than the entire Module object.
var module_ids = {};
maps.map(function (e) {
    module_ids[e.path] = {id: e.id, start: e.base};
});

var filtered_maps = new ModuleMap(function (m) {
    if (whitelist.indexOf('all') >= 0) { return true; }

    return whitelist.indexOf(m.name) >= 0;
});

// Always trust code. #Make it faster
Stalker.trustThreshold = 0;
var stalker_events = []

var target_function = undefined

// ======== For in-process fuzzing =================
var arg1  = Memory.alloc(0x100000);
var arg2  = Memory.alloc(0x100000);
var zero_0x100000 = new Uint8Array(0x100000);
// =================================================

rpc.exports = {
    // get the module maps:
    makemaps: function(args) {
        return maps;
    },

    // get the PID:
    getpid: function(args) {
        return Process.id;
    },

    // get the absolute address of a function by name
    resolvesymbol: function(symbolname) {
        return DebugSymbol.fromName(symbolname).address;
    },

    // initialize the address of the target function (to-be-hooked)
    // and attach the Interceptor
    settarget: function(target) {
        debug("Target: " + target)
        target_function = ptr(target)

        Interceptor.attach(target_function, {
            onEnter: function (args) {
                //debug('Called ------func-------: ');
                //debug("Stalker.queueCapacity=" + Stalker.queueCapacity)
                //debug("Stalker.queueDrainInterval=" + Stalker.queueDrainInterval)
                stalker_attached = true
                stalker_finished = false
                Stalker.queueCapacity = 100000000
                Stalker.queueDrainInterval = 1000*1000

                debugCov("follow")
                Stalker.follow(Process.getCurrentThreadId(), {
                    events: {
                        call: false,
                        ret: false,
                        exec: false,
                        block: false,
                        compile: true
                    },
                    onReceive: function (events) {
                        debugCov("onReceive: len(stalker_events)=" + stalker_events.length)
                        stalker_events.push(events)
                    }
                    /*onCallSummary: function (summary) {
                        console.log("onCallSummary: " + JSON.stringify(summary))
                    }*/
                });
            },
            onLeave: function (retval) {
                //debug('Leave func ');
                debugCov("unfollow")
                Stalker.unfollow(Process.getCurrentThreadId())
                debugCov("flush")
                Stalker.flush();
                if(gc_cnt % 100 == 0){
                    Stalker.garbageCollect();
                }
                gc_cnt++;
                stalker_finished = true
                //send("finished")
            }
        });
    },

    // call the target function with fuzzing payload (in-process fuzzing)
    fuzz: function (payload_hex) {
        var func_handle = undefined
        if(target_function == undefined) {
            warning("Target Function not defined!")
            return false
        }
        // Create the function handle (specify type and number of arguments)
        //func_handle = new NativeFunction(ptr(target_func), 'void', ['pointer', 'pointer']);
        func_handle = new NativeFunction(target_function, 'void', ['pointer']);

        var max_len = 100
        if(payload_hex.length > max_len*2) {
            debug("Payload trunkated from " + payload_hex.length/2 + " bytes!")
            payload_hex = payload_hex.substring(0,max_len*2);
        }	
        debug("Payload: " + payload_hex)
        debug("arg1 @ " + arg1)
        debug("arg2 @ " + arg2)

        var payload = [];
        for(var i = 0; i < payload_hex.length; i+=2)
        {
            payload.push(parseInt(payload_hex.substring(i, i + 2), 16));
        }

        // Prepare function arguments:
        payload = new Uint8Array(payload)
        Memory.writeByteArray(arg1, zero_0x100000)
        Memory.writeByteArray(arg1, payload)  // payload goes into data
        //Memory.writePointer(arg1, ptr(Number(arg1)+64))
        //Memory.writeInt(ptr(Number(arg1)+8), payload.length)

        //Memory.writePointer(ptr(Number(arg1)+16), ptr(heap1))
        ////Memory.writePointer(ptr(Number(arg1)+16), ptr(0x0))
        //
        //Memory.writeInt(ptr(Number(arg1)+24), 3)
        //Memory.writePointer(ptr(Number(arg1)+32), ptr(0x0))


        //// manage malloc/free
        //var next_buffer_index = 0

        //// Intercept malloc in order to free all allocated memory after the call:
        //Interceptor.replace(malloc, new NativeCallback(function (size) {
        //    if(size > buffers_size) {
        //        warning("malloc(" + size + ") is too large. return 0")
        //        return ptr(0)
        //    }
        //    var buf = buffers[next_buffer_index]
        //    debug("malloc(" + size + ") => [" + next_buffer_index + "] " + buf)
        //    next_buffer_index += 1
        //    return buf;
        //}, 'pointer', ['int']));

        //// Intercept calloc in order to free all allocated memory after the call:
        //Interceptor.replace(calloc, new NativeCallback(function (size) {
        //    if(size > buffers_size) {
        //        warning("calloc(" + size + ") is too large. return 0")
        //        return ptr(0)
        //    }
        //    var buf = buffers[next_buffer_index]
        //    debug("calloc(" + size + ") => [" + next_buffer_index + "] " + buf)
        //    next_buffer_index += 1
        //    return buf;
        //}, 'pointer', ['int']));

        //// Intercept free as well
        //Interceptor.replace(free, new NativeCallback(function (pointer) {
        //    debug("free(" + pointer + ")")
        //    return 0;
        //}, 'int', ['pointer']));

        //Interceptor.flush()

        debug('calling...')
        var retval = func_handle(arg1);
        debug('retval = ' + retval)

        //// free all allocated memory:
        //Interceptor.revert(malloc)
        //Interceptor.revert(calloc)
        //Interceptor.revert(free)
        //Interceptor.flush()

        return stalker_events
    },

    // check stalker state
    checkstalker: function(args) {
        debugCov("checkstalker: len(stalker_events)=" + stalker_events.length + 
                    "  stalker_{attached,finished}=" + stalker_attached + "," + stalker_finished)
        return [stalker_attached, stalker_finished];
    },
    // get the coverage
    getcoverage: function(args) {
        debugCov("getcoverage: len(stalker_events)=" + stalker_events.length)
        if(stalker_events.length == 0)
            return undefined;
        var accumulated_events = []
        for(var i = 0; i < stalker_events.length; i++) {
            var parsed = Stalker.parse(stalker_events[i], {stringify: false, annotate: false})
            accumulated_events = accumulated_events.concat(parsed);
        }
        //debugCov("cov: " + accumulated_events)
        return accumulated_events;
    },
    // clear the coverage (set empty)
    clearcoverage: function(args) {
        debugCov("clearcoverage")
        stalker_events = []
        stalker_attached = false
        stalker_finished = false
    }
};
debug("Loading JS complete")
