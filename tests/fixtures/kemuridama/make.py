"""Regenerate the Kemuridama scrub fixtures (needs Pillow). Run: python3 tests/fixtures/kemuridama/make.py
Every value is fictitious. Coordinates point at the Eiffel Tower (48.8584 N, 2.2945 E)."""
import io, os, struct, zipfile, zlib
from PIL import Image, PngImagePlugin

D = os.path.dirname(os.path.abspath(__file__))
def out(name, data): open(os.path.join(D, name), "wb").write(data)

def exif():
    e = Image.Exif()
    e[0x010F] = "FictionCam"; e[0x0110] = "FC-100 Mk II"; e[0x0131] = "FictionOS 1.0"; e[0x0132] = "2024:05:01 12:34:56"
    e[0x013B] = "Jane Example"; e[0x0112] = 6
    ex = e.get_ifd(0x8769); ex[0x9003] = "2024:05:01 12:34:56"; ex[0xA431] = "SN-0042-TEST"; ex[0xA430] = "Jane Example"
    g = e.get_ifd(0x8825)
    g[1] = "N"; g[2] = (48.0, 51.0, 30.24); g[3] = "E"; g[4] = (2.0, 17.0, 40.2); g[5] = b"\x00"; g[6] = 35.5
    g[0x1D] = "2024:05:01"
    return e.tobytes()

XMP = (b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
       b'<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" '
       b'xmp:CreatorTool="FictionEdit 3" photoshop:City="Paris"><dc:creator><rdf:Seq><rdf:li>Jane Example</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>')

img = Image.new("RGB", (16, 12), (40, 90, 160))
for x in range(16): img.putpixel((x, x % 12), (250, 200, 30))
b = io.BytesIO(); img.save(b, "JPEG", quality=90, exif=exif(), comment=b"shot from my balcony", xmp=XMP); jpg = b.getvalue()
# append trailing data (like a motion photo) after EOI
out("gps.jpg", jpg + b"TRAILER-DATA-AFTER-EOI")
b = io.BytesIO(); img.save(b, "JPEG", quality=90); out("plain.jpg", b.getvalue())

info = PngImagePlugin.PngInfo()
info.add_text("Author", "Jane Example"); info.add_text("Comment", "compressed note", zip=True)
info.add_itxt("Description", "café ünïcode", lang="en", tkey="Beschreibung")
info.add_itxt("parameters", "a castle at dusk, steps: 30", zip=True)
b = io.BytesIO(); img.save(b, "PNG", pnginfo=info, exif=exif()); p = b.getvalue()
# add a tIME chunk before IEND
t = b"tIME" + struct.pack(">HBBBBB", 2024, 5, 1, 12, 34, 56)
tchunk = struct.pack(">I", 7) + t + struct.pack(">I", zlib.crc32(t) & 0xffffffff)
p = p[:-12] + tchunk + p[-12:]
out("meta.png", p)

b = io.BytesIO(); img.save(b, "WEBP", lossless=True, exif=exif(), xmp=XMP); out("meta.webp", b.getvalue())
b = io.BytesIO(); img.convert("P").save(b, "GIF", comment=b"secret gif comment"); out("meta.gif", b.getvalue())

# minimal PDF with an Info dict (literal + UTF-16 hex string) and an XMP packet
objs = [b"<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Author (Jane \\(J\\) Example) /Title <FEFF0054006F00700020005300650063007200650074> /Creator (FictionWriter 9) /Producer (FictionPDF 1.2) /CreationDate (D:20240501123456+02'00') >>",
        b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(XMP) + XMP + b"\nendstream"]
pdf = b"%PDF-1.4\n"; offs = []
for i, o in enumerate(objs):
    offs.append(len(pdf)); pdf += b"%d 0 obj\n" % (i + 1) + o + b"\nendobj\n"
x = len(pdf)
pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
pdf += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
out("meta.pdf", pdf)

z = io.BytesIO()
with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="jpeg" ContentType="image/jpeg"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
    zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail" Target="docProps/thumbnail.jpeg"/></Relationships>')
    zf.writestr("docProps/core.xml", '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Quarterly plan</dc:title><dc:creator>Jane Example</dc:creator><cp:lastModifiedBy>John Sample</cp:lastModifiedBy><cp:revision>7</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2024-05-01T10:00:00Z</dcterms:created></cp:coreProperties>')
    zf.writestr("docProps/app.xml", '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>FictionWord</Application><Company>Example Corp</Company><TotalTime>42</TotalTime></Properties>')
    zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:ins w:id="1" w:author="John Sample" w:date="2024-05-02T00:00:00Z"><w:r><w:t>Hello</w:t></w:r></w:ins></w:body></w:document>')
    zf.writestr("word/comments.xml", '<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0" w:author="Jane Example" w:initials="JE"><w:p><w:r><w:t>check</w:t></w:r></w:p></w:comment></w:comments>')
    zf.writestr("word/media/image1.jpeg", jpg)
    zf.writestr("docProps/thumbnail.jpeg", b.getvalue()[:10] if False else open(os.path.join(D, "plain.jpg"), "rb").read())
out("meta.docx", z.getvalue())

# MP3: ID3v2.3 tag + a fake MPEG frame header + ID3v1 trailer
def frame(fid, text): body = b"\x00" + text.encode("latin1"); return fid + struct.pack(">I", len(body)) + b"\x00\x00" + body
frames = frame(b"TIT2", "Field recording") + frame(b"TPE1", "Jane Example") + frame(b"TSSE", "FictionEnc 2")
sz = len(frames); ss = bytes([(sz >> 21) & 0x7f, (sz >> 14) & 0x7f, (sz >> 7) & 0x7f, sz & 0x7f])
audio = b"\xff\xfb\x90\x64" + b"\x00" * 200
v1 = b"TAG" + b"Field recording".ljust(30, b"\0") + b"Jane Example".ljust(30, b"\0") + b"".ljust(30, b"\0") + b"2024" + b"".ljust(30, b"\0") + b"\x00"
out("meta.mp3", b"ID3\x03\x00\x00" + ss + frames + audio + v1)
print("ok")
