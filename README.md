multisig stuff to setup with mew  
  
erc20 is off for now

# How to  
  
so there're two wallets , transaction goes after you have both signatures.  
  
for this you need two wallets in mew , then deploy this contract with remix with constructor args like that `[addr1 , addr2] , 2` . addr's go with quotes.
then  
load contract from address (remix will show it) and do `stringtosend` with receiver address and how much money . `addr , 2000000`  
  
  you'll see a string. copy that what is after `string :` . better use doubleclick to select because you may select carriage_return symbol otherwise.   

 then  

 sign this stuff in both mew wallets (sign message in mew)   
  
 copy both signatures (`0x` stuff that goes after `sign.:`)  
then do `spend` in remix  with ` addr , how much , [sign1 , sign2]`. signatures go in quotes  
  
  thats all.  
  
if second wallet owner wanna check what he's offered to sign he should do 'load contract from address' aka AtAddress in remix and do 'stringtosend' himself 
  
# Side notes  
you can also use `etherscan` for all other than contract deployment.
sign's go without quotes there  
`stringtosend` is in 'Read' there , where `spend` is in 'Write'  
nifty wallet could be used when do "Connect to metamask"  
![Screen1](/bxx.jpg)