# -----------------------------------------------------------------------------
# Script: Generate-RootCertificate.ps1
# Author: Ewout van der Linden
# Date: 20-05-2018
# -----------------------------------------------------------------------------

$signature = @"

public const string Template = @"
[ ca ]
default_ca = local_ca

[ local_ca ]
dir = %RootPath%
certificate = `$dir/out/ca.pem
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/cakey.pem
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
basicConstraints = CA:false
authorityKeyIdentifier = keyid:always #,issuer:always

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ req ]
default_keyfile = %RootPath%/out/cakey.pem
default_crl_days = 7300
default_md = sha512
prompt = no
distinguished_name = root_ca_distinguished_name
x509_extensions = root_ca_extensions

[ root_ca_distinguished_name ]
commonName = %CommonName%
#organizationName = IonKiwi
#organizationalUnitName = Development

[ root_ca_extensions ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,cRLSign,keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always #,issuer:always
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

Add-Type -MemberDefinition $signature -Name CertificateMethods -Namespace CertificateUtil1

function Create-RootCA() {
	<#
		.SYNOPSIS
			Creates a root certificate
		
		.DESCRIPTION
			Creates a root certificate.
		
		.EXAMPLE
			PS C:\> Create-RootCA <subject name> <filename> <password>
			
			Description
			-----------
			Creates a root certificate
		
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
    		[string]$subjectName,
	[Parameter(
	        Position=2,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$filename,
	[Parameter(
	        Position=3,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$password
	)		
process {

$nm = [CertificateUtil1.CertificateMethods]

$openSSL = "C:\openssl\bin\openssl.exe"
$csp = "Microsoft Software Key Storage Provider" # Microsoft Enhanced RSA and AES Cryptographic Provider

$workPath = [string](Get-Location)
$configPath = [System.IO.Path]::Combine($workPath, "config");
$outputPath = [System.IO.Path]::Combine($workPath, "out");
$resultPath = [System.IO.Path]::Combine($workPath, "cert");
Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
#Remove-Item $resultPath -Force -Recurse -ErrorAction SilentlyContinue
$targetConfig = [System.IO.Path]::Combine($configPath, "ca.cnf");
$indexFile = [System.IO.Path]::Combine($outputPath, "index.txt")
$outFile = [System.IO.Path]::Combine($outputPath, "ca.pem")
$outKeyFile1 = [System.IO.Path]::Combine($outputPath, "cakey.pem")
$outCrlFile = [System.IO.Path]::Combine($outputPath, "ca.crl.pem")
$passFile = [System.IO.Path]::Combine($workPath, "capwd")
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
	$num = $nm::WriteToFile($passFile, $password);

	& $openssl ecparam -name P-521 -genkey -param_enc named_curve -out $outKeyFile1 # secp521r1
	# & $openSSL pkcs8 -topk8 -inform PEM -outform PEM -in $outKeyFile1 -out $outKeyFile2 -passout file:capwd
	& $openSSL  req -x509 -key $outKeyFile1 -days 7300 -config $targetConfig -out $outFile -passout file:capwd
	& $openSSL  ca -create_serial -config $targetConfig -gencrl -out $outCrlFile -passin file:capwd
	
	& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout file:capwd
	& $openSSL  x509 -outform der -in $outFile -out $resultFile2
	& $openSSL  crl -outform der -in $outCrlFile -out $resultFile3
}
finally {
	Remove-Item $passFile -Force
	Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
}
}
}
