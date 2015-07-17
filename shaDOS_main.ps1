Function Read-ShaDOS{

param(

[String] $metafile = $env:ShaDOS_Home,
[parameter(Mandatory=$true)]
[String] $filename
)
if((Get-Content $metafile -Stream "passwd") -eq 1){
$passwd = Read-host "Enter metafile password" -AsSecureString

try{
$meta = Get-Content $metafile -Stream "ShaDOS"
}
catch [System.Exception] {
Write-Error "Error reading metafile."
return 0
}

$meta = Decrypt-String $meta (Decrypt-Passwd $passwd)

}

else{
  try{
   $meta = Get-Content $metafile -Stream "ShaDOS"
  }
  catch [System.Exception] {
  Write-Error "Error reading metafile."
   return 0
  }
}

foreach($line in $meta){
[Array]$record = $line.Split("*")
if ($record[0] -eq $filename){
$host = $record[1]
$ads = $record[2]
$password = $record[4]

$filedata = Get-Content $host -Stream $ads
if ($password -eq $true){
$pwd = Read-Host -Prompt "Enter password" -AsSecureString
Decrypt-String $filedata (Decrypt-passwd $pwd)
}

Write-Output $filedata

}
}
}

function Get-ShaDOS{
[CmdletBinding()]
param(

[String] $metafile = $env:ShaDOS_Home
 
)
if((Get-Content $metafile -Stream "passwd") -eq 1){
$passwd = Read-Host "Metafile is password protected. Enter password" -AsSecureString
try{
[string]$encmeta = Get-Content $metafile -Stream "ShaDOS"
}
catch [System.Exception]{
Write-Error "Error reading metafile"
}

$meta = Decrypt-String $encmeta (Decrypt-Passwd $passwd)
}
else{
try{
$meta = Get-Content $metafile -Stream "ShaDOS"
}
catch [System.Exception]{
Write-Error "Error reading metafile"
}
}
foreach($line in $meta){
[Array]$record = $line.Split("*")

$filename = $record[0]
$moddate = $record[3]
$password = $record[4]

Write-Output $filename $moddate
}


} 

function Write-ShaDOS{
[CmdletBinding()]
param(
[parameter(Mandatory=$true)]
[String]$filename,
[parameter(Mandatory=$true,ValueFromPipeline=$true)]
[String[]]$destinfo,
[String] $hostfile,
[boolean]$password = $FALSE,
$metahome = $env:ShaDOS_Home
)
begin{

$hostfile =  Get-RandomHost;


if ($password){
$enckey = Read-Host -Prompt "Enter password to encrypt data:" -AsSecureString
$check = Read-Host -Prompt "confirm password:" -AsSecureString


if((Decrypt-Passwd $enckey) -eq (Decrypt-Passwd $check)){

$destinfo = Encrypt-String $destinfo (Decrypt-Passwd $enckey)


}
else{
Write-Error "Passwords do not match"
}
}

#Generate random string for data stream
$randstr = Get-RandStr


#build initial metadata string


$meta = $filename+"*"+$hostfile+"*"+$randstr+"*"+(Get-Date)+"*"+$password

#check for metafile

if($metahome -eq $NULL){
 $input = Read-Host -prompt "ShaDOS metafile is not defined. Enter a desired location, or type RANDOM for a randomized location."
  if($input -eq "RANDOM"){
   $input = Get-RandomHost
   }

   if(Test-Path $input){
   Write-host "Metafile location set to: $input"
   $metahome = $input
   [environment]::SetEnvironmentVariable("ShaDOS_Home",$input,"User")
   }
   else{
   Write-Error "File not found: $input"
   }

   $inputenc = Read-Host -prompt "Encrypt Metafile (y/n)? (recommended)"
     if($inputenc -ieq "y"){

     $encpasswd = Read-Host -Prompt "Enter password to encrypt metafile:" -AsSecureString
     $enccheck = Read-Host -Prompt "confirm password:" -AsSecureString

     if((Decrypt-Passwd $encpasswd) -eq (Decrypt-Passwd $enccheck)){

           $meta = Encrypt-String $meta (Decrypt-Passwd $encpasswd)
           Add-Content -Path $metahome -Value "1" -Stream "passwd"


    }
      else{
       Write-Error "Passwords do not match"
      }


     }
     
} #end NULL metahome condition

elseif (Get-Content $metahome -Stream "shaDOS") { 
  
  #check if encrypted
  if((Get-Content $metahome -Stream "passwd") -eq 1){
  $pass = Read-Host "Enter metafile password" -AsSecureString
  $encdata = Get-Content $metahome -Stream "shaDOS"
  $decdata = Decrypt-String $encdata (Decrypt-Passwd $pass)
  $meta += $decdata
  $meta = Encrypt-String $meta (Decrypt-Passwd $pass)
  }
  #metafile is plaintext
  else{
  $plainmeta = Get-Content $metahome -Stream "shaDOS"
  $meta += $plainmeta

  }

}

else {
Write-Error "metafile error"
}

}

process{

Add-Content -Path $hostfile -Value $destinfo -Stream $randstr
}
end{
Add-Content -Path $metahome -Value $meta -Stream "shaDOS"

#reset TrustedInstaller as file owner after writing ADS
icacls $hostfile /setowner "NT Service\TrustedInstaller"

}
}

#Randomizing Functions
#-----------------------------


function Get-RandStr {
$streamLength = Get-Random -minimum 6 -Maximum 13
$builder = New-Object System.Text.StringBuilder
$chars = @();
$i = 0;
  for($i=48;$i -le 57;$i++){
  $chars += $i;
  }
  for($i=65;$i -le 90;$i++){
  $chars += $i;
  }
  for($i=97;$i -lt 123;$i++){
  $chars += $i;
  }

for ($i=0;$i -le $streamLength; $i++){
[Void]$builder.Append([char]$chars[(Get-Random -Minimum 0 -Maximum $chars.length )]) 
}
return $builder.toString()
}


function Get-RandomHost{
$hostarray = @();
ForEach($x in (Get-ChildItem C:\Windows\SysWOW64 -Filter *.dll)){
$hostarray += $x;
}


 $randhost = $hostarray[(Get-Random -Minimum 0 -Maximum $hostarray.Length)].fullName
 
 takeown /a /f $randhost > $null


 icacls $randhost /grant Administrators:F > $null

 return $randhost
}