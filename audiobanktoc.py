import struct
import json
import sys
import string
import random
import math
import pathlib

# Variable prefix in C file and in header, can change these or set to ''
c_pfx = 'const '
h_pfx = 'extern const '

def audiobanktoc(abdata, bankinfo, cfile, hfile, bankname):
    # Counts
    numInstruments = len(bankinfo['instruments'])
    numDrums = len(bankinfo['drums'])
    numSfx = len(bankinfo['sfx'])
    
    # Const data
    inst_fields = ['loaded', 'normalRangeLo', 'normalRangeHi', 'releaseRate', 
        'envelope', 'low_sample', 'low_tuning', 'normal_sample', 'normal_tuning',
        'high_sample', 'high_tuning']
    inst_sample_fields = ['low_sample', 'normal_sample', 'high_sample']
    inst_tuning_fields = ['low_tuning', 'normal_tuning', 'high_tuning']
    drum_fields = ['releaseRate', 'pan', 'loaded', 'sample', 'tuning', 'envelope']
    sfx_fields = ['sample', 'tuning']
    sample_fields = ['len', 'sampleAddr', 'loop', 'book']
    loop_fields = ['start', 'end', 'count', 'origSpls']
    book_fields = ['order', 'npredictors']
    
    # Data structures
    inst_list = [] # The instrument list data structure addresses (includes NULLs and duplicates)
    instruments = [] # Actual instrument data
    drum_list = [] # The drum list data structure addresses (includes NULLs and duplicates)
    drums = [] # Actual drum data
    sfxes = []
    samples = [] # Sample addresses referenced, then sample dicts
    envelopes = [] # Envelope addresses referenced, then envelope dicts
    loops = []
    books = []
    all_basenames = []
    all_loop_book_addrs = []
    
    # Helper functions
    def get_ptr(a):
        if a+4 > len(abdata):
            raise RuntimeError('Invalid parse address ' + hex(a))
        ptr = struct.unpack('>I', abdata[a:a+4])[0]
        if ptr >= len(abdata) or (ptr & 3) != 0:
            raise RuntimeError('Invalid pointer ' + hex(ptr) + ' at ' + hex(a))
        return ptr
    def validate_name(name):
        if len(name) == 0 or not name.replace('_', '').isalnum():
            raise RuntimeError('Invalid name: ' + name)
        if name in all_basenames:
            raise RuntimeError('Name ' + name + ' previously used')
        all_basenames.append(name)
    def get_rand_name():
        return ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    def validate_and_add_sample(addr, name, required):
        if addr >= len(abdata) or (addr & 3) != 0:
            raise RuntimeError(name + ' invalid sample pointer: ' + hex(inst[f]))
        if addr == 0 and required:
            raise RuntimeError('Sample pointer is required in ' + name + ' but it is NULL')
        if addr != 0 and addr not in samples:
            samples.append(addr)
    def validate_tuning(f, name, splpresent):
        if not splpresent:
            if f != 0:
                raise RuntimeError('Tuning must be 0 for NULL sample')
        else:
            if not math.isfinite(f) or f > 1000.0 or f < 0.001:
                raise RuntimeError(name + ' invalid tuning: ' + str(f))
    def validate_and_add_env(addr, name):
        if addr >= len(abdata) or (addr & 3) != 0:
            raise RuntimeError(name + ' invalid envelope pointer: ' + hex(inst[f]))
        if addr != 0 and addr not in envelopes:
            envelopes.append(addr)
    def get_env_uses(addr):
        ret = []
        for inst in instruments:
            if inst['envelope'] == addr:
                ret.append(inst['basename'])
        for drum in drums:
            if drum['envelope'] == addr:
                ret.append(drum['basename'])
        assert len(ret) >= 1
        return ret
    def get_sample_uses(addr):
        ret = []
        for inst in instruments:
            if any(inst[s] == addr for s in inst_sample_fields):
                ret.append(inst['basename'])
        for drum in drums:
            if drum['sample'] == addr:
                ret.append(drum['basename'])
        for sfx in sfxes:
            if sfx['sample'] == addr:
                ret.append(sfx['basename'])
        if len(ret) == 0:
            raise RuntimeError('No uses for sample at ' + str(addr))
        return ret
    def uses_to_name(uses):
        etc = False
        if len(uses) > 3:
            uses = uses[0:3]
            uses.append('Etc')
        return '_'.join(uses)
    def validate_book_loop_addr(addr):
        if addr >= len(abdata) or (addr & 3) != 0:
            raise RuntimeError('Invalid AdpcmLoop/AdpcmBook pointer ' + hex(addr))
        if addr in all_loop_book_addrs:
            raise RuntimeError('Duplicate AdpcmLoop/AdpcmBook pointer ' + hex(addr))
        all_loop_book_addrs.append(addr)
    def addr2fullname(l, addr, allowNull=False):
        if addr == 0:
            if allowNull:
                return None
            else:
                raise RuntimeError('addr2fullname with addr 0 but NULL not allowed')
        ret = next((x['fullname'] for x in l if x['addr'] == addr), None)
        if ret is None:
            raise RuntimeError('Could not find instrument with addr ' + str(addr))
        return ret
    # Top level parse
    drumlistaddr = get_ptr(0)
    assert (numDrums == 0) == (drumlistaddr == 0)
    sfxlistaddr = get_ptr(4)
    assert (numSfx == 0) == (sfxlistaddr == 0)
    a = 8
    for i in range(numInstruments):
        inst_list.append(get_ptr(a))
        a += 4
    if numDrums > 0:
        a = drumlistaddr
        for i in range(numDrums):
            drum_list.append(get_ptr(a))
            a += 4
    
    # Instruments parse
    for i, inst_addr in enumerate(inst_list):
        inst_name = bankinfo['instruments'][i]
        if inst_addr == 0:
            if inst_name is not None:
                print('Instrument ' + str(i) + ' is NULL in bank but has a name in json (should be None)')
            continue
        if inst_name is None:
            inst_name = get_rand_name()
            print('Instrument ' + str(i) + ' is not NULL in bank but is None in json, making up random name: ' + inst_name)
        existing_inst = next((d for d in instruments if d['addr'] == inst_addr), None)
        if existing_inst is not None:
            if existing_inst['name'] != inst_name:
                print('Instrument ' + str(i) + ' already existed in bank with name ' 
                    + existing_inst['name'] + ', but json says its name is ' + inst_name)
            continue
        validate_name(inst_name)
        values = struct.unpack('>BBBBIIfIfIf', abdata[inst_addr:inst_addr+0x20])
        inst = dict(zip(inst_fields, values))
        # Validate data
        assert inst['loaded'] == 0
        assert 0 <= inst['normalRangeLo'] <= 126
        assert 0 <= inst['normalRangeHi'] <= 127
        assert inst['normalRangeHi'] == 0 or inst['normalRangeLo'] < inst['normalRangeHi']
        validate_and_add_env(inst['envelope'], 'Inst ' + str(i))
        for j in range(3):
            sf = inst_sample_fields[j]
            tf = inst_tuning_fields[j]
            splrequired = sf == 'normal_sample'
            splpresent = inst[sf] != 0
            validate_and_add_sample(inst[sf], 'Inst ' + str(i) + ' ' + sf, splrequired)
            validate_tuning(inst[tf], 'Inst ' + str(i) + ' ' + tf, splpresent)
        # Add data
        inst['addr'] = inst_addr
        inst['basename'] = inst_name
        inst['fullname'] = inst_name + '_Inst'
        instruments.append(inst)
        # print('Inst ' + str(i) + ': ' + str(inst))
    
    # Drums parse
    for i, drum_addr in enumerate(drum_list):
        drum_name = bankinfo['drums'][i]
        if drum_addr == 0:
            if drum_name is not None:
                print('Drum ' + str(i) + ' is NULL in bank but has a name in json (should be None)')
            continue
        if drum_name is None:
            drum_name = get_rand_name()
            print('Drum ' + str(i) + ' is not NULL in bank but is None in json, making up random name: ' + drum_name)
        existing_drum = next((d for d in drums if d['addr'] == drum_addr), None)
        if existing_drum is not None:
            if existing_drum['name'] != drum_name:
                print('Drum ' + str(i) + ' already existed in bank with name ' 
                    + existing_drum['name'] + ', but json says its name is ' + drum_name)
            continue
        validate_name(drum_name)
        values = struct.unpack('>BBBxIfI', abdata[drum_addr:drum_addr+0x10])
        drum = dict(zip(drum_fields, values))
        # Validate data
        assert drum['loaded'] == 0
        assert drum['pan'] <= 128
        validate_and_add_sample(drum['sample'], 'Drum ' + str(i), True)
        validate_tuning(drum['tuning'], 'Drum ' + str(i), True)
        validate_and_add_env(drum['envelope'], 'Drum ' + str(i))
        # Add data
        drum['addr'] = drum_addr
        drum['basename'] = drum_name
        drum['fullname'] = drum_name + '_Drum'
        drums.append(drum)
        # print('Drum ' + str(i) + ': ' + str(drum))
    
    # SFX parse
    a = sfxlistaddr
    for i in range(numSfx):
        sfx_name = bankinfo['sfx'][i]
        if sfx_name is None:
            sfx_name = get_rand_name()
            print('Sfx ' + str(i) + ' missing name in json, making up random name: ' + sfx_name)
        validate_name(sfx_name)
        values = struct.unpack('>If', abdata[a:a+8])
        a += 8
        sfx = dict(zip(sfx_fields, values))
        # Validate data
        validate_and_add_sample(sfx['sample'], 'Sfx ' + str(i), True)
        validate_tuning(sfx['tuning'], 'Sfx ' + str(i))
        # Add data
        sfx['basename'] = sfx_name
        sfx['fullname'] = sfx_name + '_Sfx'
        sfxes.append(sfx)
        # print('Sfx ' + str(i) + ': ' + str(sfx))
    
    # Envelopes
    for i in range(len(envelopes)):
        a = envelopes[i]
        env_name = uses_to_name(get_env_uses(a))
        env = {'addr': a,
            'fullname': env_name + '_Env',
            'points': []}
        while True:
            rate, level = struct.unpack('>hH', abdata[a:a+4])
            a += 4
            env['points'].append({'rate': rate, 'level': level})
            if rate < 0:
                break
        envelopes[i] = env
        # print('Env ' + str(i) + ': ' + str(env))
    
    # Samples
    for i in range(len(samples)):
        a = samples[i]
        values = struct.unpack('>IIII', abdata[a:a+0x10])
        sample = dict(zip(sample_fields, values))
        sample_name = uses_to_name(get_sample_uses(a))
        sample['addr'] = a
        sample['fullname'] = sample_name + '_Sample'
        validate_book_loop_addr(sample['loop'])
        validate_book_loop_addr(sample['book'])
        #
        a = sample['loop']
        values = struct.unpack('>IIII', abdata[a:a+0x10])
        a += 0x10
        loop = dict(zip(loop_fields, values))
        if loop['count'] != 0:
            loop['state'] = list(struct.unpack('>8h', abdata[a:a+0x10]))
        loop['fullname'] = sample_name + '_Loop'
        loops.append(loop)
        # print('Loop ' + str(i) + ': ' + str(loop))
        #
        a = sample['book']
        values = struct.unpack('>II', abdata[a:a+8])
        a += 8
        book = dict(zip(book_fields, values))
        elements = 8 * book['order'] * book['npredictors']
        assert elements < 10000
        if elements != 0:
            book['book'] = list(struct.unpack('>' + str(elements) + 'h', abdata[a:a+(2*elements)]))
        book['fullname'] = sample_name + '_Book'
        books.append(book)
        # print('Book ' + str(i) + ': ' + str(book))
        #
        sample['loop'] = sample_name + '_Loop'
        sample['book'] = sample_name + '_Book'
        samples[i] = sample
        # print('Sample ' + str(i) + ': ' + str(sample))
    
    # Replace addresses with fullnames
    for i in range(len(inst_list)):
        inst_list[i] = addr2fullname(instruments, inst_list[i], True)
    for i in range(len(drum_list)):
        drum_list[i] = addr2fullname(drums, drum_list[i])
    for inst in instruments:
        for f in inst_sample_fields:
            inst[f] = addr2fullname(samples, inst[f], f != 'normal_sample')
        inst['envelope'] = addr2fullname(envelopes, inst['envelope'])
    for drum in drums:
        drum['sample'] = addr2fullname(samples, drum['sample'])
        drum['envelope'] = addr2fullname(envelopes, drum['envelope'])
    for sfx in sfxes:
        sfx['sample'] = addr2fullname(samples, sfx['sample'])
        
    # Top-level struct
    bank = {'drums': bankname + '_DrumList' if numDrums > 0 else None,
        'sfx': bankname + '_SfxList' if numSfx > 0 else None,
        'instruments': inst_list}
    
    # Write
    def write_field(data, tabs):
        if isinstance(data, dict):
            cfile.write('{\n')
            for k in data.keys():
                if k in ['addr', 'basename', 'fullname']:
                    continue
                v = data[k]
                cfile.write('    ' * (tabs+1) + '.{} = '.format(k))
                write_field(v, tabs+1)
                cfile.write(',\n')
            cfile.write('    ' * tabs + '}')
        elif isinstance(data, list):
            cfile.write('{\n')
            for v in data:
                cfile.write('    ' * (tabs+1))
                write_field(v, tabs+1)
                cfile.write(',\n')
            cfile.write('    ' * tabs + '}')
        elif isinstance(data, str):
            cfile.write(data)
        elif isinstance(data, int):
            cfile.write(hex(data))
        elif isinstance(data, float):
            cfile.write(str(data))
        elif data is None:
            cfile.write('NULL')
        else:
            raise RuntimeError('Unhandled write_field type ' + str(data))
    def write_struct(type, name, data):
        brackets = ''
        if isinstance(data, list):
            brackets = '[' + str(len(data)) + ']'
        hfile.write(h_pfx + '{} {}{};\n'.format(type, name, brackets))
        cfile.write(c_pfx + '{} {}{} = \n'.format(type, name, brackets))
        write_field(data, 0)
        cfile.write(';\n\n')
    
    write_struct('AudioBank', bankname, bank)
    if numDrums > 0:
        write_struct('Drum*', bankname + '_DrumList', drum_list)
    if numSfx > 0:
        write_struct('AudioBankSound', bankname + '_SfxList', sfxes)
    for inst in instruments:
        write_struct('Instrument', inst['fullname'], inst)
    for drum in drums:
        write_struct('Drum', drum['fullname'], drum)
    for env in envelopes:
        write_struct('AdsrEnvelopePoint', env['fullname'], env['points'])
    for sample in samples:
        write_struct('AudioBankSample', sample['fullname'], sample)
    for loop in loops:
        write_struct('AdpcmLoop', loop['fullname'], loop)
    for book in books:
        write_struct('AdpcmBook', book['fullname'], book)
    

def audiobanktoc_files(abpath, bankinfopath, cpath):
    assert cpath.endswith('.c')
    with open(abpath, 'rb') as abfile, \
        open(bankinfopath, 'r') as bankinfofile, \
        open(cpath, 'w') as cfile, \
        open(cpath[:-2] + '.h', 'w') as hfile:
        abdata = abfile.read()
        bankinfo = json.loads(bankinfofile.read())
        assert all(k in bankinfo for k in ['instruments', 'drums', 'sfx'])
        bankname = pathlib.Path(cpath).stem
        assert bankname.replace('_', '').isalnum()
        audiobanktoc(abdata, bankinfo, cfile, hfile, bankname)

if __name__ == '__main__':
    try:
        abpath = sys.argv[1]
        bankinfopath = sys.argv[2]
        cpath = sys.argv[3]
    except IndexError as e:
        print('Usage: python3 audiobanktoc.py path/to/audiobank.bin path/to/bankinfo.json path/to/output.c')
        print('bankinfo.json should look like:')
        print('{"instruments": ["Strings", None, "Piano"],')
        print(' "drums": ["BassDrum", "BassDrum", "BassDrum"],')
        print(' "sfx": []')
        print('}')
        sys.exit(-1)
    audiobanktoc_files(abpath, bankinfopath, cpath)
