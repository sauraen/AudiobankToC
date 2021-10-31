import struct
import json
import sys
import string
import random
import math

def audiobanktoc(abdata, bankinfo, cfile, hfile):
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
    
    # Data structures
    inst_list = [] # The instrument list data structure addresses (includes NULLs and duplicates)
    instruments = [] # Actual instrument data
    drum_list = [] # The drum list data structure addresses (includes NULLs and duplicates)
    drums = [] # Actual drum data
    sfxes = []
    all_samples = [] # All sample addresses referenced
    all_envelopes = [] # All envelope addresses referenced
    all_names = []
    
    # Helper functions
    def get_ptr(a):
        if a+4 > len(abdata):
            raise RuntimeError('Invalid parse address ' + hex(a))
        ptr = struct.unpack('>I', abdata[a:a+4])
        if ptr >= len(abdata) or (ptr & 3) != 0:
            raise RuntimeError('Invalid pointer ' + hex(ptr) + ' at ' + hex(a))
        return ptr
    def validate_name(name):
        if len(name) == 0 or not name.replace('_', '').isalnum():
            raise RuntimeError('Invalid name: ' + name)
        if name in all_names:
            raise RuntimeError('Name ' + name + ' previously used')
        all_names.append(name)
    def get_rand_name():
        return ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    def validate_and_add_sample(addr, name):
        if addr >= len(abdata):
            raise RuntimeError(name + ' invalid sample pointer: ' + hex(inst[f]))
        if addr != 0 and addr not in all_samples:
            all_samples.append(addr)
    def validate_tuning(f, name):
        if not math.isfinite(f) or f > 1000.0 or f < 0.001:
            raise RuntimeError(name + ' invalid tuning: ' + f)
    def validate_and_add_env(addr, name):
        if addr >= len(abdata):
            raise RuntimeError(name + ' invalid envelope pointer: ' + hex(inst[f]))
        if addr != 0 and addr not in all_envelopes:
            all_samples.append(addr)
    
    # Top level parse
    drumlistaddr = get_ptr(0)
    sfxlistaddr = get_ptr(4)
    a = 8
    for i in range(numInstruments):
        inst_list.append(get_ptr(a))
        a += 4
    assert (numDrums == 0) == (drumlistaddr == 0)
    if numDrums > 0:
        a = drumlistaddr
        for i in range(numDrums):
            drumaddrs.append(get_ptr(a))
            a += 4
    
    # Instruments parse
    for i, inst_addr in enumerate(inst_list):
        inst_name = bankinfo['instruments'][i]
        if inst_addr == 0:
            if inst_name is not None:
                print('Instrument ' + str(i) + ' is NULL in bank but has a name in json (should be None)')
            continue
        if inst_name is None:
            inst_name = get_rand_name() + 'Inst'
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
        for f in inst_sample_fields:
            validate_and_add_sample(inst[f], 'Inst ' + str(i) + ' ' + f)
        for f in inst_tuning_fields:
            validate_tuning(inst[f], 'Inst ' + str(i) + ' ' + f)
        # Add data
        inst['addr'] = inst_addr
        inst['name'] = inst_name
        instruments.append(inst)
    
    # Drums parse
    for i, drum_addr in enumerate(drum_list):
        drum_name = bankinfo['drums'][i]
        if drum_addr == 0:
            if drum_name is not None:
                print('Drum ' + str(i) + ' is NULL in bank but has a name in json (should be None)')
            continue
        if drum_name is None:
            drum_name = get_rand_name() + 'Drum'
            print('Drum ' + str(i) + ' is not NULL in bank but is None in json, making up random name: ' + drum_name)
        existing_drum = next((d for d in drums if d['addr'] == drum_addr), None)
        if existing_drum is not None:
            if existing_drum['name'] != drum_name:
                print('Drum ' + str(i) + ' already existed in bank with name ' 
                    + existing_drum['name'] + ', but json says its name is ' + drum_name)
            continue
        validate_name(drum_name)
        values = struct.unpack('>BBBXIfI', abdata[inst_addr:inst_addr+0x10])
        drum = dict(zip(drum_fields, values))
        # Validate data
        assert drum['loaded'] == 0
        assert drum['pan'] <= 128
        validate_and_add_sample(drum['sample'], 'Drum ' + str(i))
        validate_tuning(drum['tuning'], 'Drum ' + str(i))
        validate_and_add_env(drum['envelope'], 'Drum ' + str(i))
        # Add data
        drum['addr'] = drum_addr
        drum['name'] = drum_name
        drums.append(drum)
    
    # SFX parse
    a = sfxlistaddr
    for i in range(numSfx):
        sfx_name = bankinfo['sfx'][i]
        if sfx_name is None:
            sfx_name = get_rand_name() + 'Sfx'
            print('Sfx ' + str(i) ' missing name in json, making up random name: ' + sfx_name)
        validate_name(sfx_name)
        values = struct.unpack('>If'), abdata[a:a+8])
        a += 8
        sfx = dict(zip(sfx_fields, values))
        # Validate data
        validate_and_add_sample(sfx['sample'], 'Sfx ' + str(i))
        validate_tuning(sfx['tuning'], 'Sfx ' + str(i))
        # Add data
        sfx['name'] = sfx_name
        sfxes.append(sfx)
    
    TODO
        
    '''
    if inst_addr == 0:
        
        inst_list.append(None)
    else:
        
    
    inst = {'name': inst_name, 'loaded': loaded, 'normalRangeLo': normalRangeLo,
        'normalRangeHi': normalRangeHi, '}
    '''
    

def audiobanktoc_files(abpath, bankinfopath, cpath):
    assert cpath.endswith('.c')
    with open(abpath, 'rb') as abfile, \
        open(bankinfopath, 'r') as bankinfofile,
        open(cpath, 'w') as cfile, \
        open(cpath[:-2] + '.h') as hfile):
        abdata = abfile.read()
        bankinfo = json.loads(bankinfofile.read())
        assert all(k in bankinfo for k in ['instruments', 'drums', 'sfx'])
        audiobanktoc(abdata, bankinfo, cfile, hfile)

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
