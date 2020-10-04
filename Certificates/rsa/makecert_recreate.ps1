# -----------------------------------------------------------------------------
# Script: Generate-ReCreateCertificateWithKey.ps1
# Author: Ewout van der Linden
# Date: 27-05-2018
# -----------------------------------------------------------------------------

$signature = @"

public const string Template1 = @"
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
certificate = `$dir/out/cert.crt
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/cert2.key
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
default_keyfile = %RootPath%/out/cert.pem

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

public const string Template2 = @"
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
default_md = sha256

policy = local_ca_policy
x509_extensions = client_extensions

copy_extensions = copy

[ local_ca_policy ]
commonName = supplied

[ client_extensions ]
basicConstraints = critical,CA:FALSE
authorityKeyIdentifier = keyid:always #,issuer:always

[ req ]
default_bits = 2048
default_keyfile = %RootPath%/out/cert.pem

default_crl_days = 5475
default_md = sha256
prompt = no
distinguished_name = client_distinguished_name
req_extensions = client_req_extensions

[ client_distinguished_name ]
commonName = %CommonName%
#organizationName = IonKiwi
#organizationalUnitName = Development

[ client_req_extensions ]
basicConstraints = critical,CA:FALSE
keyUsage = %KeyUsage%
extendedKeyUsage = %ExtendedKeyUsage%
subjectKeyIdentifier = hash
";

public static void WriteToFile(string targetFile, string content) {
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(content);
		file.Write(b, 0, b.Length);
	}
}

public static void WriteTemplate1(string rootPath, string targetFile, string commonName) {
	string sslRootPath = rootPath.Replace("\\", "/");
	string templateContent = Template1.Replace("%RootPath%", sslRootPath);
	templateContent = templateContent.Replace("%CommonName%", commonName);
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(templateContent);
		file.Write(b, 0, b.Length);
	}
}

public static void WriteTemplate2(string rootPath, string targetFile, string commonName, bool isClientAuth, bool isServerAuth) {
	string sslRootPath = rootPath.Replace("\\", "/");
	string templateContent = Template2.Replace("%RootPath%", sslRootPath);
	templateContent = templateContent.Replace("%CommonName%", commonName);
	string keyUsage, extendedKeyUsage;
	if (isClientAuth && isServerAuth) {
		keyUsage = "critical,nonRepudiation,digitalSignature,keyEncipherment,keyAgreement";
		extendedKeyUsage = "critical,serverAuth,clientAuth";
	}
	else if (isClientAuth) {
		keyUsage = "critical,nonRepudiation,digitalSignature,keyEncipherment";
		extendedKeyUsage = "critical,clientAuth";
	}
	else if (isServerAuth) {
		keyUsage = "critical,nonRepudiation,digitalSignature,keyEncipherment,keyAgreement";
		extendedKeyUsage = "critical,serverAuth";
	}
	else {
		throw new InvalidOperationException();
	}
	templateContent = templateContent.Replace("%KeyUsage%", keyUsage);
	templateContent = templateContent.Replace("%ExtendedKeyUsage%", extendedKeyUsage);
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(templateContent);
		file.Write(b, 0, b.Length);
	}
}
"@

Add-Type -MemberDefinition $signature -Name CertificateMethods -Namespace CertificateUtil4

function ReCreate-Certificate() {
	<#
		.SYNOPSIS
			Re-creates a certificate
		
		.DESCRIPTION
			Re-creates a certificate.
		
		.EXAMPLE
			PS C:\> ReCreate-Certificate <im filename> <im password> <certificate file name> <password>
			
			Description
			-----------
			Re-creates a certificate.
		
		.OUTPUTS
			Success or failure
		
		.NOTES
			Author: Ewout van der Linden
			Created: 27-05-2018
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
    		[string]$certificateFile,
	[Parameter(
	        Position=4,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$false)]
    		[string]$password
	)
process {

$nm = [CertificateUtil4.CertificateMethods]

$openSSL = "C:\openssl\bin\openssl.exe"
$csp = "Microsoft Software Key Storage Provider" # Microsoft Enhanced RSA and AES Cryptographic Provider

$workPath = [string](Get-Location)
if (![System.IO.Path]::IsPathRooted($certificateFile)) {
	$certificateFile = [System.IO.Path]::Combine($workPath, $certificateFile);
}
$imBaseName = $certificateFile.Substring(0, $certificateFile.LastIndexOf('.'));
$i = $imBaseName.LastIndexOf('\');
if ($i -ge 0) {
	$imBaseName = $imBaseName.Substring($i + 1);
}
$filename = $imBaseName;
$configPath = [System.IO.Path]::Combine($workPath, "config");
$outputPath = [System.IO.Path]::Combine($workPath, "out");
$resultPath = [System.IO.Path]::Combine($workPath, "cert");
Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
#Remove-Item $resultPath -Force -Recurse -ErrorAction SilentlyContinue
$imFile = [System.IO.Path]::Combine($workPath, $imFilename);
$imTempFile1 = [System.IO.Path]::Combine($outputPath, "_im.crt");
$imTempFile2 = [System.IO.Path]::Combine($outputPath, "_im2.key");
$targetConfig = [System.IO.Path]::Combine($configPath, "cert.cnf");
$indexFile = [System.IO.Path]::Combine($outputPath, "index.txt")
$outFile = [System.IO.Path]::Combine($outputPath, "cert.crt")
$outKeyFile1 = [System.IO.Path]::Combine($outputPath, "cert.key")
$outKeyFile2 = [System.IO.Path]::Combine($outputPath, "cert2.key")
$outRequestFile = [System.IO.Path]::Combine($outputPath, "cert.csr")
$outCrlFile = [System.IO.Path]::Combine($outputPath, "cert.crl.pem")
$passFile1 = [System.IO.Path]::Combine($workPath, "impwd")
$passFile2 = [System.IO.Path]::Combine($workPath, "certpwd")
$resultFile1 = [System.IO.Path]::Combine($resultPath, "$filename.pfx")
$resultFile2 = [System.IO.Path]::Combine($resultPath, "$filename.cer")
$resultFile3 = [System.IO.Path]::Combine($resultPath, "$filename.crl")
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
New-Item -ItemType Directory -Path $resultPath -Force | Out-Null
$num = $nm::WriteToFile("$indexFile.attr", "unique_subject = no");
New-Item $indexFile -ItemType file | Out-Null
try {
	$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificateFile, $password)
	$subjectName = $cert.Subject.Substring(3);
	$isServer = $false
	$isClient = $false
	foreach ($extension in $cert.Extensions)
	{
		if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension])
		{
			$eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension
			foreach ($oid in $eku.EnhancedKeyUsages)
			{
				if ($oid.FriendlyName -eq 'Server Authentication') { $isServer = $true }
				if ($oid.FriendlyName -eq 'Client Authentication') { $isClient = $true }
			}
		}
	}
	if ($isServer -or $isClient) {
		$num = $nm::WriteTemplate2($workPath, $targetConfig, $subjectName, $isClient, $isServer);
		$num = $nm::WriteToFile($passFile1, $imPassword);
		$num = $nm::WriteToFile($passFile2, $password);
		
		& $openSSL  pkcs12 -in $imFile -out $imTempFile1 -nokeys -clcerts -passin file:impwd
		& $openSSL  pkcs12 -in $imFile -nocerts -nodes -out $imTempFile2 -passin file:impwd
		& $openSSL  pkcs12 -in $certificateFile -nocerts -nodes -out $outKeyFile1 -passin file:certpwd
		
		#& $openSSL  genrsa -out $outKeyFile1 2048
		& $openSSL  pkcs8 -topk8 -inform PEM -outform PEM -in $outKeyFile1 -out $outKeyFile2 -passout file:certpwd
		& $openSSL  req -new -config $targetConfig -key $outKeyFile2 -out $outRequestFile -passin file:certpwd
		& $openSSL  ca -batch -create_serial -config $targetConfig -days 5475 -notext -in $outRequestFile -out $outFile -passin file:impwd
		
		& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout file:certpwd
		& $openSSL  x509 -outform der -in $outFile -out $resultFile2
	}
	else {
		$num = $nm::WriteTemplate1($workPath, $targetConfig, $subjectName);
		$num = $nm::WriteToFile($passFile1, $imPassword);
		$num = $nm::WriteToFile($passFile2, $password);
		
		& $openSSL  pkcs12 -in $imFile -out $imTempFile1 -nokeys -clcerts -passin file:impwd
		& $openSSL  pkcs12 -in $imFile -nocerts -nodes -out $imTempFile2 -passin file:impwd
		& $openSSL  pkcs12 -in $certificateFile -nocerts -nodes -out $outKeyFile1 -passin file:certpwd
		
		#& $openSSL  genrsa -out $outKeyFile1 4096
		& $openSSL  pkcs8 -topk8 -inform PEM -outform PEM -in $outKeyFile1 -out $outKeyFile2 -passout file:certpwd
		& $openSSL  req -new -config $targetConfig -key $outKeyFile2 -out $outRequestFile -passin file:certpwd
		& $openSSL  ca -batch -create_serial -config $targetConfig -days 5475 -notext -in $outRequestFile -out $outFile -passin file:impwd
		& $openSSL  ca -name local_im -create_serial -config $targetConfig -gencrl -out $outCrlFile -passin file:certpwd
		
		& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout file:certpwd
		& $openSSL  x509 -outform der -in $outFile -out $resultFile2
		& $openSSL  crl -outform der -in $outCrlFile -out $resultFile3
	}
}
finally {
	Remove-Item $passFile1 -Force
	Remove-Item $passFile2 -Force
	Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
}
}
}
