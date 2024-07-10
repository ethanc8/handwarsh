import re
import zlib
import olefile
import struct
import sys
import pathlib

# If FreeCAD is installed with conda, importing `freecad` will set `sys.path` to the correct value
try: import freecad
except: pass

InFreeCAD = True
try: FreeCAD
except NameError: InFreeCAD = False

if InFreeCAD:
    #FREECADPATH = "/home/matt/Downloads/freecad-build_771/lib"  # path to FreeCADApp.dll, FreeCADGui, freecadBase.dll ecc.. file
    #sys.path.append(FREECADPATH)
    import FreeCAD
    from FreeCAD import Vector, Rotation  # treat as vectors; need rotation for ellipse
    import Part

class Buffer(object):
    def __init__(self, data):
        self.data = data
        self.i = 0

    def int8(self):
        self.i += 1
        return struct.unpack('>b', self.data[self.i - 1].to_bytes(1, "little"))[0]  # MattC

    # return struct.unpack('>b', self.data[self.i-1])[0] #MattC
    def uint8(self):
        self.i += 1
        return struct.unpack('>B', self.data[self.i - 1].to_bytes(1, "little"))[0]  # MattC

    # return struct.unpack('>B', self.data[self.i-1])[0] #MattC commented out
    def int16(self):
        self.i += 2
        return struct.unpack('>h', self.data[self.i - 2:self.i])[0]

    def uint16(self):
        self.i += 2
        return struct.unpack('>H', self.data[self.i - 2:self.i])[0]

    def int32(self):
        self.i += 4
        return struct.unpack('>l', self.data[self.i - 4:self.i])[0]

    def uint32(self):
        self.i += 4
        return struct.unpack('>L', self.data[self.i - 4:self.i])[0]

    def double(self):
        self.i += 8
        return struct.unpack('>d', self.data[self.i - 8:self.i])[0]

    def string(self, size):
        self.i += size
        return self.data[self.i - size:self.i]

    def databuf(self, size):
        self.i += size
        return list(map(ord, self.data[self.i - size:self.i]))

    def char(self):
        return chr(self.uint8())

    def ptr(self):
        r, q = self.int16(), 0
        if r < 0:
            q = self.int16()
            r = -r
        return q * 32767 + r - 1

    def end(self):
        return self.i == len(self.data)

    def read_field(self, datatype, ne, var_size):
        if ne == 1:
            assert var_size != -1
            ne = var_size
        if ne != 0:
            return [self.read_field(datatype, 0, 0) for i in range(ne)]

        if datatype == 'u' or datatype == 'n': #MattC check
            return self.uint8()
        elif datatype == 'c':
            return self.int8()
        elif datatype == 'l':
            v = self.uint8()
            if not v in range(0,1+1):
                print("PROBLEM ?? should be 0/1>>", v)
            #assert v in (0, 1)
            return v == 1
        elif datatype == 'd':
            return self.int32()
        elif datatype == 'p':
            return self.ptr()
        elif datatype == 'f':
            return self.double()
        elif datatype == 'v':
            return [self.double(), self.double(), self.double()]
        elif datatype == 'b':
            return [
                self.double(), self.double(), self.double(),
                self.double(), self.double(), self.double()
            ]
        elif datatype == 'h':
            return [self.double(), self.double(), self.double()]
        else:
            raise Exception('Unknown field datatype %r' % datatype)


def load_schema(fn):
    lines = open(fn, 'r').read().strip().split('\n')
    while not lines[0].startswith(': SCHEMA FILE'):
        lines = lines[1:]
    assert lines[-1].startswith('**************** end of schema')
    lines = lines[2:-1]

    node_types = {}
    cur_node = None
    for line in lines:
        if line.find(' ') < line.find(';'):  # node type
            type_name, desc, tx_nf_var = line.split('; ')
            datatype, name = type_name.strip().split(' ')
            datatype = int(datatype)
            tx, nf, var = tx_nf_var.strip().split(' ')
            node_types[datatype] = [name, desc, tx == '1', var == '1', []]
            cur_node = node_types[datatype][4]
        elif cur_node is not None:
            name, datatype, tx_nc_ne = line.split('; ')
            tx, nc, ne = tx_nc_ne.strip().split(' ')
            if tx == '1':
                cur_node.append((name, datatype, int(nc), int(ne)))

    return node_types

def PStoFC(datatype, mygeom, index, fname, bufferreadfield):
    #This could probably be streamlined to one call outside of a loop in read_x_b
    if datatype == 31:  # CIRCLE
        for x in mygeom:
            if x[0] == datatype:
                for y in x:
                    if isinstance(y, list):
                        if y[0] == index:
                            if fname == 'centre':
                                y.append(['centre', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'normal':
                                y.append(['normal', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'x_axis':
                                y.append(['x_axis', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'radius':
                                y.append(['radius', bufferreadfield])
                            elif fname == 'next':
                                y.append(['next', bufferreadfield])
                            elif fname == 'previous':
                                y.append(['previous', bufferreadfield])
                            elif fname == 'node_id':
                                y.append(['node_id', bufferreadfield])
                            elif fname == 'owner':
                                y.append(['owner', bufferreadfield])
                            elif fname == 'identifier':
                                y.append(['identifier', bufferreadfield])
                                print(bufferreadfield)  # this is a float
    if datatype == 51:  # CYLINDER
        for x in mygeom:
            if x[0] == datatype:
                for y in x:
                    if isinstance(y, list):
                        if y[0] == index:
                            if fname == 'pvec':
                                y.append(['centre', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                            elif fname == 'axis':
                                y.append(['normal', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'x_axis':
                                y.append(['x_axis', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'radius':
                                y.append(['radius', bufferreadfield])
                                print(bufferreadfield)  # this is a float
                            elif fname == 'next':
                                y.append(['next', bufferreadfield])
                            elif fname == 'previous':
                                y.append(['previous', bufferreadfield])
                            elif fname == 'node_id':
                                y.append(['node_id', bufferreadfield])
                            elif fname == 'owner':
                                y.append(['owner', bufferreadfield])
                            elif fname == 'identifier':
                                y.append(['identifier', bufferreadfield])
    if datatype == 50:  # PLANE
        for x in mygeom:
            if x[0] == datatype:
                for y in x:
                    if isinstance(y, list):
                        if y[0] == index:
                            if fname == 'pvec':
                                y.append(['centre', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'normal':
                                y.append(['normal', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            elif fname == 'x_axis':
                                y.append(['x_axis', bufferreadfield[0], bufferreadfield[1], bufferreadfield[2]])
                                print(bufferreadfield[0], bufferreadfield[1], bufferreadfield[2])
                            #elif fname == 'radius':
                            #    y.append(['radius', bufferreadfield])
                            #    print(bufferreadfield)  # this is a float
                            elif fname == 'next':
                                y.append(['next', bufferreadfield])
                            elif fname == 'previous':
                                y.append(['previous', bufferreadfield])
                            elif fname == 'node_id':
                                y.append(['node_id', bufferreadfield])
                            elif fname == 'owner':
                                y.append(['owner', bufferreadfield])
                            elif fname == 'identifier':
                                y.append(['identifier', bufferreadfield])

    return mygeom

def read_x_b(data_path=None,outfile_path=None):
    #https://github.com/armthethinker/LGBTQ_VR_Museum/tree/df3c3084ee6decd5c9d8204134076fe207671da7/VRLiDARFromScratch/Assets/Plugins/PixyzPluginForUnity/Editor/Bin/PsSchema
    schema = load_schema('parasolid_schemas/sch_13006.sch_txt')
    #schema = load_schema('parasolid_schemas/sch_14000.sch_txt')

    data_file = open(data_path, 'rb')
    data = bytearray(data_file.read())
    data_file.close()

    outfile = open(outfile_path, 'wt') #MattC
    mygeom = []  # MattC
    mynodes = [] # MattC

    # Load header

    if data.startswith(b'*'): #MattC to bytes
        eoh = b'**END_OF_HEADER*****************************************************************\n' #MattC to bytes
        eoh_pos = data.find(eoh)
        header, data = data[:eoh_pos] + eoh, data[eoh_pos + len(eoh):]
        outfile.write(f"header = x_b_header {{\n")
        outfile.write(header) #MattC
        outfile.write(f'\n}};\n') #MattC
    assert data[:4] == b'PS\0\0'

    # Load head metadata

    buf = Buffer(data[4:])

    str1 = buf.string(buf.int16()) #MattC
    outfile.write(f'str1 = "{str1.decode()}";\n')
    str2 = buf.string(buf.int32()) #MattC
    outfile.write(f'str2 = "{str2.decode()}";\n')
    user_field_size = buf.int16()
    outfile.write(f"user_field_size = {user_field_size};\n") #MattC

    unk = buf.int32()
    assert unk == 0
    outfile.write(f"unk = {unk};\n")

    # Load all the nodes

    outfile.write("nodes = [\n")

    types_seen = []
    while not buf.end():
        datatype = buf.int16()
        if datatype == 1:
            outfile.write('1 __terminator__ {\n')
            terminator_a = buf.uint16()
            outfile.write(f"    terminator_a: {terminator_a};\n")
            assert terminator_a == 1
            terminator_b = buf.end()
            outfile.write(f"    terminator_b: {terminator_b};\n")
            if terminator_b:
                outfile.write('    // EOF ok\n')
            else:
                outfile.write('    // Problem ?\n')
            outfile.write("}\n")
            break
        if datatype in schema:
            name, desc, tx, var, fields = schema[datatype]
            outfile.write(f"{datatype} {name} {{\n")
            # If this is the first time we've seen this node type, then
            # it comes with a schema
            if datatype not in types_seen:
                outfile.write("    __schema__: {\n")
                types_seen.append(datatype)
                nf = buf.uint8()
                if nf != 0xFF:
                    new_fields = []
                    ptr = 0
                    while True:
                        c = buf.char()
                        if c == 'C':
                            outfile.write('        Appended fields: '+(str(fields[ptr]))+'\n') #MattC
                            new_fields.append(fields[ptr])
                            ptr += 1
                        elif c == 'D':
                            outfile.write('        Deleted field: '+(str(fields[ptr]))+'\n') #MattC
                            ptr += 1
                        elif c == 'I' or c == 'A':
                            if c == 'I':
                                outfile.write('        Inserting field:\n') #MattC
                            else:
                                outfile.write('        Appending field:\n') #MattC
                            fname = buf.string(buf.uint8())
                            ptr_class = buf.uint16()
                            fne = buf.ptr()
                            if ptr_class != 0:
                                ftype = 'p'
                            else:
                                ftype = buf.string(buf.uint8()).decode('utf-8')  # MattC
                            if fne == 1:
                                xmt_code = buf.uint8()
                            try:
                                outfile.write('            '+(str(new_fields[-1])+'\n')) #MattC
                                new_fields.append((fname.decode('utf-8'), ftype, ptr_class, fne))  # MattC
                            except:
                                outfile.write("            // Ignore below; = KLUDGE to work around problem chars")
                                outfile.write('            PROB chars?'+(str(new_fields[-1])+'\n')) #MattC
                                new_fields.append(('UNKNOWN', ftype, ptr_class, fne))  # MattC
                        elif c == 'Z':
                            break
                        else:
                            outfile.write('        Unknown schema character %r\n' % c) #MattC
                            #raise Exception('Unknown schema character %r' % c) #MattC
                    schema[datatype][4] = new_fields
                    fields = new_fields
                outfile.write("    },\n")
            assert tx
            if var:
                var_size = buf.int32()
                outfile.write(f"    __variable_size__: {var_size};\n") #MattC
            else:
                var_size = -1
            node = {} # MattC not used ????
            index = buf.int16()
            outfile.write(f"    __index__: {index};\n") #MattC

            mygeom.append([datatype, [index]])
            mynodes.append([index, datatype, var_size, fields])

            for fname, ftype, nc, ne in fields:
                #print('\t' + fname, buf.read_field(ftype, ne, var_size)) #MattC
                bufferreadfield = buf.read_field(ftype, ne, var_size) #MattC
                outfile.write(f"    {fname}: {bufferreadfield};\n")  # MattC
                #Proof of concept test ...#MattC
                #May need to change this to not collecting by datatype??
                mygeom = PStoFC(datatype, mygeom, index, fname, bufferreadfield) #MattC
            outfile.write("},\n") # end this node

        else:
            print('unknown datatype:', datatype)
            outfile.write(f"{datatype} __unknown__ {{}}, // fatal error: unknown datatype\n")
            assert False
    outfile.write("]\n") # end "nodes"
    outfile.close() #MattC
    return mygeom , mynodes#MattC
    
def hexdump(data):
    data = bytearray(data)
    for i in range(0, len(data), 16):
        hc = ''
        ac = ''
        for j in range(16):
            if i + j >= len(data):
                hc += '   '
                ac += ' '
            else:
                hc += '%02x ' % ((data[i + j]))
                if chr(data[
                           i + j]) in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=~`[]{}\\;:\'"|./>?,<':
                    ac += chr(data[i + j])
                else:
                    ac += '.'
            if j == 7:
                hc += ' '
                ac += ' '
        print('%08x  %s | %s' % (i, hc, ac))

def readFile(afile, adirname, indent, parentname):
    sectionname = afile.name.encode("utf-8")  # becomes a byte array
    startflag = None
    if sectionname[0] in [0x01, 0x02, 0x05]: #some OLE components begin with these characters
        startflag = sectionname[0]
        sectionname = sectionname[1:].decode("utf-8")
    else:
        sectionname = sectionname.decode("utf-8")

    print(indent + "File, flag : ", sectionname, startflag)
    return
def readDir(adir, adirname, indent, pname):
    print(indent + "Dir, entries  : ", adir.name, len(adir))
    for entries in adir:
        readEntry(entries, adirname,indent+" --> ", pname)

def readEntry(entry, ename, indent, pname):
    if entry.isfile:
        readFile(entry, ename, indent, pname)
    elif entry.isdir:
        readDir(entry, entry.name, indent, pname)
    else:
        print("nothing to do")
    return

#program starts here ...

magic1 = b'\x14\x00\x06\x00\x08\x00' #incl in zlib
magic2 = b'\x23\x1D\xD5\x71\xDA\x81\x48\xA2\xA8\x58\x98\xB2\x1B\x89\xEF\x99' # marker for geometry
zlib_hdr = b'\x78\x01'
xml_hdr = b'\x3C\x3F\x78\x6D\x6C'
png_hdr = b'\x89\x50\x4E\x47'
parasolid_hdr = b'PS\x00\x00'

sldprt_path = sys.argv[1]
sldprt_name = str(pathlib.Path(sldprt_path).name)
sldprt_folder = pathlib.Path(sldprt_path).parent

magics = [magic1,zlib_hdr,xml_hdr,png_hdr,parasolid_hdr]

OLEbased = False

print(sldprt_path)

try:
    assert olefile.isOleFile(sldprt_path)
    OLEbased = True
except:
    OLEbased = False

print("OLE based : ", OLEbased)

geofiles = []

if not OLEbased:
    with open(sldprt_path, 'rb') as sldprt_file:
        data = sldprt_file.read()
        file_size = sldprt_file.tell()
        #print(file_size)

        markers_zlib = re.finditer(zlib_hdr, data)
        magicspots_zlib = [line.start() for line in markers_zlib]
        #print(len(magicspots_zlib))

        for z in magicspots_zlib:
            #print("START ",z)
            hexdump(data[z-16:z+16])

            decomp_n = int.from_bytes(data[z-8:z-4],'little')
            #print(decomp_n) #decompressed size
            hexdump(data[z-8:z-4])

            comp_n = int.from_bytes(data[z-4:z],'little')
            #print(comp_n) #compress size
            hexdump(data[z-4:z])

            if decomp_n>0:
                zlibobj = zlib.decompressobj()
                data_decomp = zlibobj.decompress(data[z:z+comp_n],decomp_n)
                if data_decomp[0:4] == parasolid_hdr:
                    hexdump(data_decomp)
                    if data_decomp.find(b'TRANSMIT FILE (deltas)') > 0:
                        open(sldprt_folder / ('mytestgeomdelta'+ ('_%i') % z + '_deltas.x_b'), 'wb').write(data_decomp)
                        geofiles.append(sldprt_folder / ('mytestgeomdelta'+ ('_%i') % z + '_deltas.x_b'))
                    else:
                        open(sldprt_folder / ('mytestgeom' + ('_%i') % z + '.x_b'), 'wb').write(data_decomp)
                        geofiles.append(sldprt_folder / ('mytestgeom' + ('_%i') % z + '.x_b'))
            '''
            png_locns = [l for l in re.finditer(png_hdr, data_decomp)]
            geometry_locns = [l for l in re.finditer(magic2, data_decomp)]
            zlibposs_locns = [l for l in re.finditer(zlib_hdr, data_decomp)]
            xml_locns = [l for l in re.finditer(xml_hdr, data_decomp)]
            #hexdump(data_decomp[0:64])
            print('geom ', geometry_locns)
            print('poss zlib ', zlibposs_locns)
            print('png locns', png_locns)
            print('xml locns', xml_locns)
            if len(png_locns) > 0:
                open('mytest_%i.png' % cl, 'wb').write(data_decomp)
            elif len(xml_locns) > 0 :
                open('mytest_%i.xml' % cl, 'wb').write(data_decomp)
            elif len(geometry_locns) > 0:
                locns_start = [l.start() for l in geometry_locns]
                previouslocn = 0
                for j, x in enumerate(locns_start):
                    offset_temp = x - 4  # -24
                    if 1:  # try:
                        #data_comp_2_hdr1 = data_decomp[(0 + offset_temp):(4 + offset_temp)]  # unknown
                        #hexdump(data_comp_2_hdr1)
                        #data_comp_2_hdr2 = data_decomp[(4 + offset_temp):(4 + 16 + offset_temp)]  # signature?
                        data_comp_2_size_comp = data_decomp[(4 + 16 + offset_temp):(4 + 16 + 4 + offset_temp)]
                        data_comp_2_size_decomp = data_decomp[
                                                    (4 + 16 + 4 + offset_temp):(4 + 16 + 4 + 4 + offset_temp)]
                        data_comp_2_size_comp_n = int.from_bytes(data_comp_2_size_comp, 'little')
                        data_comp_2_size_decomp_n = int.from_bytes(data_comp_2_size_decomp, 'little')
                        # print('>>>>',data_comp_2_size_comp_n,data_comp_2_size_decomp_n)
                        unused_len = 0
                        zlibobj2 = zlib.decompressobj()  # reinitialize bc can't reuse
                        # hexdump(data_decomp[0:48])
                        # print(len(data_decomp[(28+offset_temp):]))
                        # quit()
                        data_decomp2 = zlibobj2.decompress(data_decomp[(28 + offset_temp):],
                                                            unused_len)  # skip ahead to where \x78\x01 should be
                        unused_len = len(zlibobj2.unused_data)
                        if unused_len > 0:
                            print(">>>> length of unused data : ", unused_len)
                            if unused_len <= 32:
                                hexdump(zlibobj2.unused_data)
                        # open('mytestgeom' + ('_%i_%i.x_b' % (i,j)), 'wb').write(data_decomp2)
                        if data_decomp2[0:4] == parasolid_hdr:
                            if data_decomp2.find(b'TRANSMIT FILE (deltas)') > 0:
                                open('mytestgeom' + ('_%i_%i' % (cl, j)) + '_deltas.x_b', 'wb').write(data_decomp2)
                                geofiles.append('mytestgeom' + ('_%i_%i' % (cl, j)) + '_deltas.x_b')
                            else:
                                open('mytestgeom' + ('_%i_%i') % (cl, j) + '.x_b', 'wb').write(data_decomp2)
                                geofiles.append('mytestgeom' + ('_%i_%i') % (cl, j) + '.x_b')
                        else:
                            print("not a parasolid block????")
                        previouslocn += len(data_decomp2) + 28  # update locn in block add back header length
                        #success = True
                    # except:
                    #    print('failure at secondary decompression')
                    #    success = False
            else:
                print("we have something else ...")
            '''

elif OLEbased:
    #there can be different kinds of files in this type of archive.  .xlsx, .docx, etc in addition to
    #SW geometry.  That compression schemes is ZIP.  Some of the SW elements are themselves compressed
    # using ZLIB, with first 16 bytes being a header(?) followed by 8 bytes, the first four of which
    # are the length of the compressed data.  Remaining four are length of uncompressed data???
    #In any case, the SW geometry is compress using ZLIB and begins with 4 bytes: b'PS\0\0'

    with olefile.OleFileIO(sldprt_path) as ole:
        dirlist = ole.listdir()
        for d in dirlist:
            print(d)
            test = ole.openstream(d)
            data = test.read()
            datalen = len(data)

            magiclocns = re.finditer(magic2, data) #find geom
            magicspots = [line.start() for line in magiclocns]
            print(magicspots)
            hexdump(data[:48])
            #for idx, magicloc in enumerate(magiclocns):
            for idx in magicspots:
                #prevlocn = magicloc.start()-4
                prevlocn = idx - 4
                if 1:
                    print(data[(prevlocn+4+0):(prevlocn+4+16)])
                    print(magic2)
                    if data[(prevlocn+4+0):(prevlocn+4+16)] == magic2:
                        zobj = zlib.decompressobj()
                        dsize = (int.from_bytes(data[(prevlocn+20):(prevlocn+24)],'little'))
                        csize = (int.from_bytes(data[(prevlocn+24):(prevlocn+28)],'little'))
                        data_comp = data[(prevlocn+28):]
                        data_decomp = zobj.decompress(data_comp, dsize)
                        print(len(data_decomp))
                        print(">>>>",len(zobj.unused_data)) #TODO check on this
                        if data_decomp[0:4] == parasolid_hdr:
                            if data_decomp.find(b'TRANSMIT FILE (deltas)')>0:
                                open(sldprt_folder / (sldprt_name + ('_%i' % idx) + '_deltas.x_b'), 'wb').write(data_decomp)
                                geofiles.append(sldprt_folder / (sldprt_name + ('_%i' % idx) + '_deltas.x_b'))
                            else:
                                open(sldprt_folder / (sldprt_name + ('_%i' % idx) + '.x_b'), 'wb').write(data_decomp)
                                geofiles.append(sldprt_folder / (sldprt_name + ('_%i' % idx) + '.x_b'))
                        prevlocn += (datalen-len(zobj.unused_data))
                        #print("unknown",int.from_bytes(data_comp[prevlocn:(prevlocn+4)],'little'))
                        prevlocn += 4
                        #print("unknown",int.from_bytes(data_comp[prevlocn:(prevlocn+4)],'little'))
                        prevlocn += 4
                        print(prevlocn)
                    else:
                        hexdump(data[(prevlocn+4+0):(prevlocn+4+16)])
                        print('hmmm')

            magiclocns = re.finditer(png_hdr, data)
            for idx, magicloc in enumerate(magiclocns):
                print("PNGS")
                prevlocn = magicloc.start()-4
                if 1:
                    hexdump(data[(prevlocn + 4 + 0):(prevlocn + 4 + 16)])
                    #if data[(prevlocn+4+0):(prevlocn+4+16)] == magics[1]:
                    try:
                        #zobj = zlib.decompressobj()
                        data_comp = data[(prevlocn+4):]
                        #data_decomp = zobj.decompress(data_comp)
                        open(sldprt_name + ('_%i' % idx) +'.png','wb').write(data_comp)
                        print(sldprt_name + ('_%i' % idx) +'.png')
                        print(data_comp[0:64])
                        prevlocn += len(data_comp)
                    except:
                        hexdump(data[(prevlocn+4+0):(prevlocn+4+16)])
                        print('hmmm')
                        pass
    ole.close()
else:
    print('shouldnt get here')

print(geofiles)

if not geofiles:
    print("No geometry was created")
else:
    for g in geofiles:
        if str(g).find("deltas") == -1:
            thegeometry = None
            #THIS OLD VERSION HAS A PROBLEM IF THERE ARE NURBS OBJECTS IT SEEMS.  INDEXING GOES GOOFY
            thegeometry, thegeometry2 = read_x_b(data_path=g, outfile_path=sldprt_folder / f"{g.name}_debuginfo.txt")




