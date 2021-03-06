# -----------------------------------------------------------------------------
# Script: Generate-IntermediateEndCertificate.ps1
# Author: Ewout van der Linden
# Date: 20-05-2018
# -----------------------------------------------------------------------------

$signature = @"

public const string Template = @"
[ ca ]
default_ca = local_ca

[ local_ca ]
dir = %RootPath%
certificate = `$dir/out/_im.crt
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/_im2.key
serial = `$dir/out/serial

default_crl_days = 5475
default_md = sha512

policy = local_ca_policy
x509_extensions = im_ca_extensions

copy_extensions = copy

[ local_im ]
dir = %RootPath%
certificate = `$dir/out/imend.crt
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/imend2.key
serial = `$dir/out/serial

default_crl_days = 5475
default_md = sha512

policy = local_ca_policy
x509_extensions = local_ca_extensions
crl_extensions = crl_ext

copy_extensions = copy

[ local_ca_policy ]
commonName = supplied

[ local_ca_extensions ]
basicConstraints = critical,CA:FALSE
authorityKeyIdentifier = keyid:always #,issuer:always

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ im_ca_extensions ]
basicConstraints = critical,CA:TRUE,pathlen:0
authorityKeyIdentifier = keyid:always #,issuer:always

[ req ]
default_bits = 4096
default_keyfile = %RootPath%/out/imend.pem

default_crl_days = 5475
default_md = sha512
prompt = no
distinguished_name = im_ca_distinguished_name
req_extensions = im_ca_req_extensions

[ im_ca_distinguished_name ]
commonName = %CommonName%
#organizationName = IonKiwi
#organizationalUnitName = Development

[ im_ca_req_extensions ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,cRLSign,keyCertSign
subjectKeyIdentifier = hash
";

public static void WriteToFile(string targetFile, string content) {
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(content);
		file.Write(b, 0, b.Length);
	}
}

public static void WriteTemplate(string rootPath, string targetFile, string commonName) {
	string sslRootPath = rootPath.Replace("\\", "/");
	string templateContent = Template.Replace("%RootPath%", sslRootPath);
	templateContent = templateContent.Replace("%CommonName%", commonName);
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(templateContent);
		file.Write(b, 0, b.Length);
	}
}
"@

Add-Type -MemberDefinition $signature -Name CertificateMethods -Namespace CertificateUtil3

function Create-IntermediateEndCertificate() {
	<#
		.SYNOPSIS
			Creates a intermediate end certificate
		
		.DESCRIPTION
			Creates a intermediate end certificate.
		
		.EXAMPLE
			PS C:\> Create-IntermediateEndCertificate <im filename> <im password> <subject name> <certificate file name> <password>
			
			Description
			-----------
			Creates a intermediate end certificate
		
		.OUTPUTS
			Success or failure
		
		.NOTES
			Author: Ewout van der Linden
			Created: 20-05-2018
	#>
	[CmdletBinding()]
	param(
	[Parameter(
	        Position=1,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$imFilename,
	[Parameter(
	        Position=2,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$imPassword,
	[Parameter(
	        Position=3,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$subjectName,
	[Parameter(
	        Position=4,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$filename,
	[Parameter(
	        Position=5,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$password
	)
process {

$nm = [CertificateUtil3.CertificateMethods]

$openSSL = "C:\openssl\bin\openssl.exe"
$csp = "Microsoft Software Key Storage Provider" # Microsoft Enhanced RSA and AES Cryptographic Provider

$workPath = [string](Get-Location)
$configPath = [System.IO.Path]::Combine($workPath, "config");
$outputPath = [System.IO.Path]::Combine($workPath, "out");
$resultPath = [System.IO.Path]::Combine($workPath, "cert");
Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
#Remove-Item $resultPath -Force -Recurse -ErrorAction SilentlyContinue
$imFile = [System.IO.Path]::Combine($workPath, $imFilename);
$imTempFile1 = [System.IO.Path]::Combine($outputPath, "_im.crt");
$imTempFile2 = [System.IO.Path]::Combine($outputPath, "_im2.key");
$targetConfig = [System.IO.Path]::Combine($configPath, "imend.cnf");
$indexFile = [System.IO.Path]::Combine($outputPath, "index.txt")
$outFile = [System.IO.Path]::Combine($outputPath, "imend.crt")
$outKeyFile1 = [System.IO.Path]::Combine($outputPath, "imend.key")
$outKeyFile2 = [System.IO.Path]::Combine($outputPath, "imend2.key")
$outRequestFile = [System.IO.Path]::Combine($outputPath, "imend.csr")
$outCrlFile = [System.IO.Path]::Combine($outputPath, "imend.crl.pem")
$passFile1 = [System.IO.Path]::Combine($workPath, "impwd")
$passFile2 = [System.IO.Path]::Combine($workPath, "imendpwd")
$resultFile1 = [System.IO.Path]::Combine($resultPath, "$filename.pfx")
$resultFile2 = [System.IO.Path]::Combine($resultPath, "$filename.cer")
$resultFile3 = [System.IO.Path]::Combine($resultPath, "$filename.crl")
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
New-Item -ItemType Directory -Path $resultPath -Force | Out-Null
New-Item $indexFile -ItemType file | Out-Null
$num = $nm::WriteToFile("$indexFile.attr", "unique_subject = no");
$num = $nm::WriteTemplate($workPath, $targetConfig, $subjectName);
try {
	$num = $nm::WriteToFile($passFile1, $imPassword);
	$num = $nm::WriteToFile($passFile2, $password);
	
	& $openSSL  pkcs12 -in $imFile -out $imTempFile1 -nokeys -clcerts -passin file:impwd
	& $openSSL  pkcs12 -in $imFile -nocerts -nodes -out $imTempFile2 -passin file:impwd
	
	& $openSSL  genrsa -out $outKeyFile1 4096
	& $openSSL  pkcs8 -topk8 -inform PEM -outform PEM -in $outKeyFile1 -out $outKeyFile2 -passout file:imendpwd
	& $openSSL  req -new -config $targetConfig -key $outKeyFile2 -out $outRequestFile -passin file:imendpwd
	& $openSSL  ca -batch -create_serial -config $targetConfig -days 5475 -notext -in $outRequestFile -out $outFile -passin file:impwd
	& $openSSL  ca -name local_im -create_serial -config $targetConfig -gencrl -out $outCrlFile -passin file:imendpwd
	
	& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout file:imendpwd
	& $openSSL  x509 -outform der -in $outFile -out $resultFile2
	& $openSSL  crl -outform der -in $outCrlFile -out $resultFile3
}
finally {
	Remove-Item $passFile1 -Force
	Remove-Item $passFile2 -Force
	Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
}
}
}
