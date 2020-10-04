# -----------------------------------------------------------------------------
# Script: Generate-IntermediateCertificate.ps1
# Author: Ewout van der Linden
# Date: 20-05-2018
# -----------------------------------------------------------------------------

$signature = @"

public const string Template = @"
[ ca ]
default_ca = local_ca

[ local_ca ]
dir = %RootPath%
certificate = `$dir/out/_ca.pem
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/_cakey.pem
serial = `$dir/out/serial

default_crl_days = 7300
default_md = sha512

policy = local_ca_policy
x509_extensions = im_ca_extensions

copy_extensions = copy

[ local_im ]
dir = %RootPath%
certificate = `$dir/out/im.crt
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/im2.key
serial = `$dir/out/serial

default_crl_days = 7300
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
basicConstraints = critical,CA:TRUE
authorityKeyIdentifier = keyid:always #,issuer:always

[ req ]
default_bits = 4096
default_keyfile = %RootPath%/out/im.pem

default_crl_days = 7300
default_md = sha512
prompt = no
distinguished_name = im_ca_distinguished_name
req_extensions = im_ca_req_extensions

[ im_ca_distinguished_name ]
commonName = %CommonName%
#organizationName = IonKiwi
#organizationalUnitName = Development

[ im_ca_req_extensions ]
basicConstraints = critical,CA:TRUE
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

Add-Type -MemberDefinition $signature -Name CertificateMethods -Namespace CertificateUtil5

function Create-CertificateRevocationList() {
	<#
		.SYNOPSIS
			Creates a certificate revocation list
		
		.DESCRIPTION
			Creates a certificate revocation list.
		
		.EXAMPLE
			PS C:\> Create-CertificateRevocationList <ca file> <ca password> <filename>
			
			Description
			-----------
			Creates a certificate revocation list
		
		.OUTPUTS
			Success or failure
		
		.NOTES
			Author: Ewout van der Linden
			Created: 17-06-2018
	#>
	[CmdletBinding()]
	param(
	[Parameter(
	        Position=1,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$caFilename,
	[Parameter(
	        Position=2,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$caPassword,
	[Parameter(
	        Position=3,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$filename
	)
process {

$nm = [CertificateUtil5.CertificateMethods]

$openSSL = "C:\openssl\bin\openssl.exe"
$csp = "Microsoft Software Key Storage Provider" # Microsoft Enhanced RSA and AES Cryptographic Provider

$workPath = [string](Get-Location)
$configPath = [System.IO.Path]::Combine($workPath, "config");
$outputPath = [System.IO.Path]::Combine($workPath, "out");
$resultPath = [System.IO.Path]::Combine($workPath, "cert");
Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
#Remove-Item $resultPath -Force -Recurse -ErrorAction SilentlyContinue
$caFile = [System.IO.Path]::Combine($workPath, $caFilename);
$caTempFile1 = [System.IO.Path]::Combine($outputPath, "im.crt");
$caTempFile2 = [System.IO.Path]::Combine($outputPath, "im2.key");
$targetConfig = [System.IO.Path]::Combine($configPath, "im.cnf");
$indexFile = [System.IO.Path]::Combine($outputPath, "index.txt")
$outCrlFile = [System.IO.Path]::Combine($outputPath, "im.crl.pem")
$passFile1 = [System.IO.Path]::Combine($workPath, "capwd")
$resultFile = [System.IO.Path]::Combine($resultPath, "$filename.crl")
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
New-Item -ItemType Directory -Path $resultPath -Force | Out-Null
New-Item $indexFile -ItemType file | Out-Null
$num = $nm::WriteToFile("$indexFile.attr", "unique_subject = no");
$num = $nm::WriteTemplate($workPath, $targetConfig, $subjectName);
try {
	$num = $nm::WriteToFile($passFile1, $caPassword);
	
	& $openSSL  pkcs12 -in $caFile -out $caTempFile1 -nokeys -clcerts -passin file:capwd
	& $openSSL  pkcs12 -in $caFile -nocerts -nodes -out $caTempFile2 -passin file:capwd
	
	& $openSSL  ca -name local_im -create_serial -config $targetConfig -gencrl -out $outCrlFile -passin file:capwd
	
	& $openSSL  crl -outform der -in $outCrlFile -out $resultFile
}
finally {
	Remove-Item $passFile1 -Force
	Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
}
}
}
