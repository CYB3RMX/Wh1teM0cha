# Wh1teM0cha
<img src="https://img.shields.io/badge/-Python-black?style=for-the-badge&logo=python&logoColor=white">
<p align="center">
<img src="https://github.com/CYB3RMX/Wh1teM0cha/assets/61325408/322d3083-cb78-4630-ae71-1ae33f5dc543" width="400" style="margin=auto;">
  <br>
<br><b>Python Module for Parsing & Reverse Engineering Mach-O Executables.</b><br>
</p>
<br>

# Installation
- <i>You can simply run this command.</i>
```bash
pip3 install wh1tem0cha
```

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

