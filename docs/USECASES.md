# How to Use
## General Information About Target Binary
- <i>Description</i>: With this feature you can get general information from target MACH-O binary.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_binary_info()
```
![wm1](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/42cb05f0-22d4-47fb-bf4c-ba8b1c3a36a1)

## List Segments
- <i>Description</i>: This method is for parsing and listing segments.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_segments()
```
![wm2](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/065dd2ca-30be-4d6d-bdfb-8a55d6f64690)

### Get Target Segment Information
- <i>Description</i>: With this method you can get additional information about the target segment.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.segment_info("__TEXT")
```
![wm3](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/c6022cde-975f-4f95-b813-9daf7bccb37c)

### Dump Segment Buffer
- <i>Description</i>: This method is for extracting content of the target segment.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.dump_segment("__TEXT")
```
![wm9](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/9faebf16-bbac-4a24-a5ae-5f8d77739f20)

## List Sections
- <i>Description</i>: This method is for parsing and listing sections.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_sections()
```
![wm4](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/474f9105-bfd4-40a4-80d9-48e55246194d)

### Get Target Section Information
- <i>Description</i>: With this method you can get additional information about the target section.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.section_info("__text")
```
![wm5](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/15555c54-bee2-4aa8-b649-5883f8148790)

### Dump Section Buffer
- <i>Description</i>: This method is for extracting content of the target section.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.dump_section("__text")
```

![wmm1](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/fbb65f74-4bf8-4214-8c2f-5ab92629ba41)

## Get DYLIB Information
- <i>Description</i>: This method is for get all information about the Dynamic Libraries.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_dylib_names()
```

![wm6](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/74c86094-3efd-4e5e-b87a-53b7e579cdf1)

### Get WEAK DYLIB Information
- <i>Description</i>: This method is for get all information about the Weak Dynamic Libraries.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_weak_dylib_names()
```
![wm7](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/b3100164-66c6-4d10-adb8-4126eef680ee)

## Dump Strings
- <i>Description</i>: This method can get and list string values from the target binary file.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_strings()
```
![wm8](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/11de879f-a1f1-4e35-802d-4f6ceb9ace6e)

## Gather Application Identifier
- <i>Description</i>: This method returns application identifier name. (For example "com.example.app")<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.application_identifier()
```

![wmm2](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/cfe7e608-e955-49ec-acf3-96549038eff2)

## Gather Code Signature Information
- <i>Description</i>: This method is for getting information about code signature section.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.code_signature_info()
```

![wmm3](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/c345ac23-7a01-41d7-807a-ab6448d4f6a0)

## Getting LC_SYMTAB Information
- <i>Description</i>: This method returns information about LC_SYMTAB.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_symtab_info()
```

![wmm4](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/23b351ea-bca0-46e5-859e-feec4ca6c0a3)

### List SYMTAB Strings
- <i>Description</i>: This method returns string values contained in LC_SYMTAB.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.dump_symtab_strings()
```

![wmm5](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/4531b1ab-1121-4309-90ab-b2f468e9b017)

## Gather Information About Dynamic Linking Editor (LC_DYLD_INFO)
- <i>Description</i>: This method returns information about LC_DYLD_INFO.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_dyld_info()
```

![wmm7](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/c0cccf9c-7234-4abe-9e0a-7eb89ab513a1)

## Parsing Property List Data
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
plist = wm.get_plists()

for pl in plist[0].iter():
    if pl.text:
        print(pl.text)
```

![wmm8](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/2d517796-cfe2-46d5-bbbd-59aac9e28673)

## Locating Entrypoint Offset
- <i>Description</i>: This method returns entrypoint offset of the target binary.<br>
```python
from wh1tem0cha import Wh1teM0cha

wm = Wh1teM0cha("target_binary_file")
wm.get_entrypoint()
```

![wmm6](https://github.com/CYB3RMX/Wh1teM0cha/assets/42123683/a52d04e2-108a-4316-b6dd-47b7f71987e5)
