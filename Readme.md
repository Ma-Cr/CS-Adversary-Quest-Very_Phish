# Catapult Spider - Very Phish   
---
### Challenge Description   
    
CATAPULT SPIDER is running a new malware campaign. Still primarily motivated by their greed for more Dogecoin they are now distributing a new malware loader via email. We were approached by a company that had the misfortune of having their data encrypted. Without proper EDR they were only able to identify a suspicious file that was sent to one of their employees via email. We are not sure what this file is and how it managed to infect the host, but it most likely is some type of loader that downloads further components from their command and control server. Sadly the command and control server has since been taken offline. However, we were able to find another command and control server at 116.202.161.100. This server is active, but we will need your expertise to find additional samples. Can you help us identify the trick the loader used and track down further samples that were downloaded by the loader?    
   
---
### Challenge Solution    
    
The first file in the challenge is a compiled HTML document:    
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712185644.png?raw=true)    
This can be extracted to the source with `7z x filename`. After extracting it with 7zip, I was left with a few files. The relevant one looks to be `doc.htm` which has an encoded powershell command in it.     
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712185740.png?raw=true)    
After base64 decoding it, the powershell encoded command appears to be a small script which is downloading something with `Net.WebClient` and executing it with `Start-Process`.    
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712185819.png?raw=true)    
At this point, I moved over to a Windows machine to decode the `$xs` variable and work through the powershell script. I started by declaring and using the `Get-Decode` function within the powershell script which is base64 decoding a string, passing it to UTF-8, and then XOR'ing the resulting characters with 42. That left me with a list including a few filenames such as encrypter.exe or control.exe.     
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712190548.png?raw=true)     
The last line in the encoded powershell command is a loop for each object in a split statement on the list that was just decoded. I broke the contents for the for each loop into separate steps to make it a bit more readable.      
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712191832.png?raw=true)     
`$l` is being declared as a list which will be used for the format string in the `DownloadFile` call near the end of the loop. The first element in the list is then `$t` which is declared just before the loop with `$t=(([int64]($s.split(',')[0])-[uint32]::MaxValue).tostring("x8"))`. This is taking the first list item (7527234048), subtracting the max value of an unsigned 32-bit integer (4294967295), and then taking the hex representation (c0a87a01). This resulting hex value is used roughly in the middle of the format string.       
The second item in the list is the SHA256 hash of `$t`. The third is `$_` which is referencing the object passed in the for each loop (the filename in this case). The fourth item is just "http", and the fifth is the second item in the list that was decoded which is 42666. The sixth is ":", seventh is "/", and the eighth item is "0x".        
These items are then combined in a formatted string within the `DownloadFile` call. From here, I just built the formatted string by hand, knowing the indexes of `$t` listed above. The first item would then be `http[:]//0xc0a87a01:42666/C84BEE34284DA6BBDD16859BB9B961D8A3B32D49D6276676F46798EA510034E4/encrypter.exe` which would be downloaded with that `DownloadFile` call, saved to the temp folder which is retrieved through the environment variables, and executed with `Start-Process`.
However, the challenge states that the threat actor has taken 0xc0a87a01 down, but 116.202.161.100 has been identified as still active. The first step would then be to convert 116.202.161.100 to hex and substitute that for `$t` in the formatted string.  
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712192116.png?raw=true)       
The new C2 IP in hex representation would then be 74caa164. Since that hex is used in two places in the URL (destination and directory), the SHA256 hash for it still has to be computed. In powershell, that hash can be found with a modified command from the script:      
`(Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]"74caa164")) -Algorithm SHA256).hash`      
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712193334.png?raw=true)       
The first file from the new C2 would then be `http[:]//0x74caa164:42666/F5D3271FE6D59C185D85353DFB8794A4FF9B7BDD5661FCCF356766998B6D276B/encrypter.exe`. However, encrypter.exe on this new infrastucture isn't found, but ransomnote_flag.exe is under `http[:]//0x74caa164:42666/F5D3271FE6D59C185D85353DFB8794A4FF9B7BDD5661FCCF356766998B6D276B/ransomnote_flag.exe`.      
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712193118.png?raw=true)             
The ransomnote_flag.exe file is indeed a PE executable:
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712193218.png?raw=true)         
From here, I just used strings to find the flag for this challenge.
![Screenshot](https://github.com/Ma-Cr/CS-Adversary-Quest-Very_Phish/blob/main/imgs/Pasted%20image%2020220712193149.png?raw=true)     