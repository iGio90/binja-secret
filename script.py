def get_script(module_name, target):
    script = 'var sleepingTarget;'
    script += 'var sleeps = [];'
    script += 'var base;'
    script += 'var target;'
    script += '''
        function sendStuffsAndWait(c) {
            console.log('-> now in context of: ' + base.add(target));   
            var ranges = {};
            send("1:::" + target + ":::" + JSON.stringify(c));
            
            for (reg in c) {
                var range;
                try {
                    range = Process.findRangeByAddress(ptr(c[reg]));
                } catch(err) {
                    continue;
                }
                if (range !== null && typeof range['file'] === 'undefined') {
                    if (typeof ranges[range.base] === 'undefined') {
                        ranges[range.base] = range
                    }        
                }
            }
            
            for (r in ranges) {
                var range = ranges[r];
                try {
                    Memory.protect(range.base, range.size, 'rwx')
                    send("2:::" + target + ":::" + range.base, Memory.readByteArray(range.base, range.size));
                } catch(err) {}
            }
            
            sleepingTarget = sleeps.length;
            var ss = sleeps.length;
            sleeps[sleepingTarget] = true;
            console.log('-> sleeping: ' + base.add(target) + ' with targetId ' + ss);
            while(sleeps[ss]) {
                Thread.sleep(1 / 50);
            }
        }    
    '''
    script += 'setTimeout(function() {'
    script += 'var m = Process.findModuleByName("' + module_name + '");'
    script += 'base = m.base;'
    script += 'target = ' + target + ';'
    script += '''
            send('3:::' + target + ':::' + base + ':::' + m.size)
            console.log('-> attaching to: ' + base.add(target));
            Interceptor.attach(base.add(target), function() {
                sendStuffsAndWait(this.context, target);            
            });
        }, 500);
        '''
    return script + '''
        rpc.exports = {
            dumprange: function(addr) {
                var range = Process.findRangeByAddress(ptr(addr));
                if (range === null) {
                    return null;
                }
                try {
                    Memory.protect(range.base, range.size, 'rwx');
                    return Memory.readByteArray(range.base, range.size);                
                } catch(err) {
                    return null;
                }
            }
        }
    '''