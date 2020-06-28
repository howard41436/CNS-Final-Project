# CNS-Final-Project
A Privacy-Preserving Campus Access Control System

## Requirement
- Install charm
(Reference: https://github.com/JHUISI/charm/tree/aded57440f23a9a75d7f09ee1d6d0392bed7b39f)
```
pip3 install bitarray
```

## Step
1. Generate keys
```
python3 key_gen.py
```
2. Scheme
	1. For VLR:
		- Modify `GS_PROTOCOL` to `VLRSig` in `const.py`
	2. For ShortSig:
		- Modify `GS_PROTOCOL` to `ShortSig` in `const.py`
3. Testing
	1. Run school server.
	```
	sh run_school_server.sh
	```  
	2. CDC sends revocation list to school at the beginning of the day.
	```
	python3 cdc.py
	```
	3. Run `student.py` to enter buildings.
	```
	python3 student.py
	```
	4. If a student is diagnosed, run `cdc.py` to trigger an diagnosed event.
	```
	python3 cdc.py
	```

## Example
1. 1st day (6/30):
	1. CDC sends revocation list to school.
	2. Student 1 & 2 enter DerTian(4).
	3. Student 3 enters MingDa(8).
2. 2nd day (7/1):
	1. CDC sends revocation list to school.
	2. Student 1 enters LuMing(6).
	3. Student 3 enters XiaoFu(10).
	4. Student 1 diagnosed.
	5. CDC triggers an diagnosed event (with information printed).
3. 3rd day (7/2):
	1. CDC sends revocation list to school.
	2. Student 1 & 2 & 3 try to enter DerTian(4).
	$\Rightarrow$ Only student 3 can enter DerTian(4).
4. 16th day (7/15) (After 13 days):
	1. CDC sends revocation list to school.
	2. Student 1 & 2 & 3 try to enter DerTian(4).
	$\Rightarrow$ Only student 3 can enter DerTian(4).
5. 17th day (7/16) (After 14 days):
	1. CDC sends revocation list to school.
	2. Student 2 can enter DerTian(4) now. (If he/she is not diagnosed.) 

