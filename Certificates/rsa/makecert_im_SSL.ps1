# -----------------------------------------------------------------------------
# Script: Generate-EndCertificate.ps1
# Author: Ewout van der Linden
# Date: 27-05-2018
# -----------------------------------------------------------------------------

$signature = @"

public const string Template = @"
[ ca ]
default_ca = local_ca

[ local_ca ]
dir = %RootPath%
certificate = `$dir/out/_imend.crt
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/_imend2.key
serial = `$dir/out/serial

default_crl_days = 5475
default_md = sha256

policy = local_ca_policy
x509_extensions = server_extensions

copy_extensions = copy

[ local_ca_policy ]
commonName = supplied

[ server_extensions ]
basicConstraints = critical,CA:FALSE
authorityKeyIdentifier = keyid:always #,issuer:always

[ req ]
default_bits = 2048
default_keyfile = %RootPath%/out/server.pem

default_crl_days = 5475
default_md = sha256
prompt = no
distinguished_name = server_distinguished_name
req_extensions = server_req_extensions

[ server_distinguished_name ]
commonName = %CommonName%
#organizationName = IonKiwi
#organizationalUnitName = Development

[ server_req_extensions ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage = critical,serverAuth
subjectKeyIdentifier = hash
";

public static void WriteToFile(string targetFile, string content) {
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(content);
		file.Write(b, 0, b.Length);
	}
}

public static void WriteTemplate(string rootPath, string targetFile, string commonName, bool clientAuth, string dnsNamesCSV, string ipsCSV) {
	string sslRootPath = rootPath.Replace("\\", "/");
	string templateContent = Template.Replace("%RootPath%", sslRootPath);
	templateContent = templateContent.Replace("%CommonName%", commonName);
	
	if (clientAuth) {
		templateContent = templateContent.Replace("extendedKeyUsage = critical,serverAuth", "extendedKeyUsage = critical,serverAuth,clientAuth");
	}
	
	if (!string.IsNullOrEmpty(dnsNamesCSV) || !string.IsNullOrEmpty(ipsCSV)) {
		templateContent += "\r\nsubjectAltName = @alt_names\r\n[alt_names]\r\n";
	}
	
	string[] dnsNames = dnsNamesCSV == null ? new string[0] : dnsNamesCSV.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries).Select(z => z.Trim()).ToArray();
	for (int i = 0; i < dnsNames.Length; i++) {
		templateContent += "DNS." + (i + 1) + " = " + dnsNames[i] + "\r\n";
	}
	
	string[] ips = ipsCSV == null ? new string[0] : ipsCSV.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries).Select(z => z.Trim()).ToArray();
	for (int i = 0; i < ips.Length; i++) {
		templateContent += "IP." + (i + 1) + " = " + ips[i] + "\r\n";
	}
	
	using (var file = System.IO.File.Open(targetFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite)) {
		var b = new System.Text.UTF8Encoding(false, true).GetBytes(templateContent);
		file.Write(b, 0, b.Length);
	}
}
"@

Add-Type -MemberDefinition $signature -Name SSLCertificateMethods -Namespace CertificateUtil -UsingNamespace "System.Linq"

function Create-EndCertificate() {
	<#
		.SYNOPSIS
			Creates a end certificate
		
		.DESCRIPTION
			Creates a end certificate.
		
		.EXAMPLE
			PS C:\> Create-EndCertificate <im filename> <im password> <subject> <dns names> <certificate filename> <password>
			
			Description
			-----------
			Creates a end certificate
		
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
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$imFilename,
	[Parameter(
	        Position=2,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$imPassword,
	[Parameter(
	        Position=3,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$subjectName,
	[Parameter(
	        Position=4,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$dnsNames,
	[Parameter(
	        Position=5,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$ipNames,
	[Parameter(
	        Position=6,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[switch]$clientAuth,
	[Parameter(
	        Position=7,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$filename,
	[Parameter(
	        Position=8,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$password
	)
process {

$nm = [CertificateUtil.SSLCertificateMethods]

$openSSL = "C:\openssl\bin\openssl.exe"
$csp = "Microsoft Software Key Storage Provider" # Microsoft Enhanced RSA and AES Cryptographic Provider

$workPath = [string](Get-Location)
#$imBaseName = $imFilename.Substring(0, $imFilename.LastIndexOf('.'));
#$filename = $imBaseName + "-STS";
$configPath = [System.IO.Path]::Combine($workPath, "config");
$outputPath = [System.IO.Path]::Combine($workPath, "out");
$resultPath = [System.IO.Path]::Combine($workPath, "cert");
Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
#Remove-Item $resultPath -Force -Recurse -ErrorAction SilentlyContinue
$imFile = [System.IO.Path]::Combine($workPath, $imFilename);
$imTempFile1 = [System.IO.Path]::Combine($outputPath, "_imend.crt");
$imTempFile2 = [System.IO.Path]::Combine($outputPath, "_imend2.key");
$targetConfig = [System.IO.Path]::Combine($configPath, "server.cnf");
$indexFile = [System.IO.Path]::Combine($outputPath, "index.txt")
$outFile = [System.IO.Path]::Combine($outputPath, "server.crt")
$outKeyFile1 = [System.IO.Path]::Combine($outputPath, "server.key")
$outKeyFile2 = [System.IO.Path]::Combine($outputPath, "server2.key")
$outRequestFile = [System.IO.Path]::Combine($outputPath, "server.csr")
$passFile1 = [System.IO.Path]::Combine($workPath, "imendpwd")
$passFile2 = [System.IO.Path]::Combine($workPath, "serverpwd")
$resultFile1 = [System.IO.Path]::Combine($resultPath, "$filename.pfx")
$resultFile2 = [System.IO.Path]::Combine($resultPath, "$filename.cer")
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
New-Item -ItemType Directory -Path $resultPath -Force | Out-Null
New-Item $indexFile -ItemType file | Out-Null
$num = $nm::WriteToFile("$indexFile.attr", "unique_subject = no");
$num = $nm::WriteTemplate($workPath, $targetConfig, $subjectName, $clientAuth, $dnsNames, $ipNames);
try {
	$num = $nm::WriteToFile($passFile1, $imPassword);
	$num = $nm::WriteToFile($passFile2, $password);
	
	& $openSSL  pkcs12 -in $imFile -out $imTempFile1 -nokeys -clcerts -passin file:imendpwd
	& $openSSL  pkcs12 -in $imFile -nocerts -nodes -out $imTempFile2 -passin file:imendpwd
	
	& $openSSL  genrsa -out $outKeyFile1 2048
	& $openSSL  pkcs8 -topk8 -inform PEM -outform PEM -in $outKeyFile1 -out $outKeyFile2 -passout file:serverpwd
	& $openSSL  req -new -config $targetConfig -key $outKeyFile2 -out $outRequestFile -passin file:serverpwd
	& $openSSL  ca -batch -create_serial -config $targetConfig -days 5475 -notext -in $outRequestFile -out $outFile -passin file:imendpwd
	
	& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout file:serverpwd
	& $openSSL  x509 -outform der -in $outFile -out $resultFile2
}
finally {
	Remove-Item $passFile1 -Force
	Remove-Item $passFile2 -Force
	Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
}
}
}
