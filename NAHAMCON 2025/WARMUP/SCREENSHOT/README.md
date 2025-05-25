![image](https://github.com/user-attachments/assets/7b391517-d016-4ee6-b989-231d68127548)

## Challenge

In this Challenge, we are provided with Screenshot.png which is a screnshot of zip files. 

## Solution
To solve this, we need to recover the files.

![Screenshot](https://github.com/user-attachments/assets/4e74db2c-25e3-4576-bcbb-406795d8889a)


Here's the hex values to be copy: 
```
504b03043300010063002f02b55a00000000430000002700000008000b00666c61672e74787401990700020041450300003d42ffd1b35f95031424f68b65c3f57669f14e8df0003fe240b3ac3364859e4c2dbc3c36f2d4acc403761385afe4e3f90fbd29d91b614ba2c6efde11b71bcc907a72ed504b01023f033300010063002f02b55a00000000430000002700000008002f000000000000002080b48100000000666c61672e7478740a00200000000000010018008213854307cadb01000000000000000000000000000000000199070002004145030000504b0506000000000100010065000000740000000000
```
After that, save it as flag.hex

We already know that it suppose to be zip file so we shall then rebuild the file from hex to zip
```
xxd -r -p flag.hex flag.zip
```

the password is there from the challenge description
```
unzip -P password flag.zip
```
![image](https://github.com/user-attachments/assets/c5e7add6-e581-4e21-878c-caedd1efcff6)

```
flag{907e5bb257cd5fc818e88a13622f3d46}
```
