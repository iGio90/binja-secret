def get_script(module_name, target):
    script = 'var m, base, target;'
    script += 'var moduleName = "' + module_name + '";'
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
                if (range !== null) {
                    if (typeof range['file'] !== 'undefined') {
                        continue;
                    }
                    if (typeof ranges[range.base] === 'undefined') {
                        ranges[range.base] = range
                    }
                }
            }
            
            for (r in ranges) {
                var range = ranges[r];
                try {
                    send("2:::" + target + ":::" + range['base'], Memory.readByteArray(range['base'], range['size']));
                } catch(err) {
                    console.log('-> error dumping range ' + range['base'] + ': ' + err);
                }
            }
            
            console.log('-> sleeping: ' + base.add(target));
            while(true) {
                Thread.sleep(1 / 50);
            }
        }    
    '''
    script += 'setTimeout(function() {'
    script += 'm = Process.findModuleByName(moduleName);'
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
            rangeinfo: function(addr) {
                var range = Process.findRangeByAddress(ptr(addr));
                if (range === null) {
                    return null;
                }
                return {
                    'base': range.base,
                    'size': range.size
                };                
            },
            dumprange: function(addr, len) {
                try {
                    var p = ptr(addr);
                    Memory.protect(p, len, 'rwx');
                    return Memory.readByteArray(p, len);
                } catch(err) {
                    return null;
                }
            }
        }
    '''