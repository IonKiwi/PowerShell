# -----------------------------------------------------------------------------
# Script: Generate-SelfCertificate.ps1
# Author: Ewout van der Linden
# Date: 27-05-2018
# -----------------------------------------------------------------------------

$signature = @"

public const string Template = @"
[ ca ]
default_ca = local_ca

[ local_ca ]
dir = %RootPath%
certificate = `$dir/out/server-self.pem
database = `$dir/out/index.txt
new_certs_dir = `$dir/out
private_key = `$dir/out/server-selfkey2.pem
serial = `$dir/out/serial

default_crl_days = 7300
default_md = sha384

policy = local_ca_policy
x509_extensions = local_ca_extensions

copy_extensions = copy

[ local_ca_policy ]
commonName = supplied

[ local_ca_extensions ]
basicConstraints = CA:false
authorityKeyIdentifier = keyid:always #,issuer:always

[ req ]
default_crl_days = 7300
default_md = sha384
prompt = no
distinguished_name = root_ca_distinguished_name
x509_extensions = root_ca_extensions

[ root_ca_distinguished_name ]
commonName = %CommonName%
#organizationName = IonKiwi
#organizationalUnitName = Development

[ root_ca_extensions ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,nonRepudiation,digitalSignature,keyEncipherment,keyAgreement,keyCertSign
extendedKeyUsage = critical,serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always #,issuer:always
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

Add-Type -MemberDefinition $signature -Name SSLSelfCertificateMethods -Namespace CertificateUtil -UsingNamespace "System.Linq"

function Create-SelfSignedSSL() {
	<#
		.SYNOPSIS
			Creates a self-signed SSL certificate
		
		.DESCRIPTION
			Creates a self-signed SSL certificate.
		
		.EXAMPLE
			PS C:\> Create-SelfSignedSSL <subject> <dns names> <certificate filename> <password>
			
			Description
			-----------
			Creates a self-signed SSL certificate
		
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
    		[string]$subjectName,
	[Parameter(
	        Position=2,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$dnsNames,
	[Parameter(
	        Position=3,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$ipNames,
	[Parameter(
	        Position=4,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[switch]$clientAuth,
	[Parameter(
	        Position=5,
        	Mandatory=$true,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$filename,
	[Parameter(
	        Position=6,
        	Mandatory=$false,
        	ValueFromPipeline=$false,
        	ValueFromPipelineByPropertyName=$true)]
    		[string]$password
	)
process {

$nm = [CertificateUtil.SSLSelfCertificateMethods]

$openSSL = "C:\openssl\bin\openssl.exe"
$csp = "Microsoft Software Key Storage Provider" # Microsoft Enhanced RSA and AES Cryptographic Provider

$workPath = [string](Get-Location)
$configPath = [System.IO.Path]::Combine($workPath, "config");
$outputPath = [System.IO.Path]::Combine($workPath, "out");
$resultPath = [System.IO.Path]::Combine($workPath, "cert");
Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
#Remove-Item $resultPath -Force -Recurse -ErrorAction SilentlyContinue
$targetConfig = [System.IO.Path]::Combine($configPath, "server-self.cnf");
$indexFile = [System.IO.Path]::Combine($outputPath, "index.txt")
$outFile = [System.IO.Path]::Combine($outputPath, "server-self.pem")
$outKeyFile1 = [System.IO.Path]::Combine($outputPath, "server-selfkey.pem")
# $outRequestFile = [System.IO.Path]::Combine($outputPath, "server.csr")
$passFile1 = [System.IO.Path]::Combine($workPath, "endpwd")
$resultFile1 = [System.IO.Path]::Combine($resultPath, "$filename.pfx")
$resultFile2 = [System.IO.Path]::Combine($resultPath, "$filename.cer")
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
New-Item -ItemType Directory -Path $resultPath -Force | Out-Null
New-Item $indexFile -ItemType file | Out-Null
$num = $nm::WriteToFile("$indexFile.attr", "unique_subject = no");
$num = $nm::WriteTemplate($workPath, $targetConfig, $subjectName, $clientAuth, $dnsNames, $ipNames);
try {
	$noPassword = !$password
	if (!$password) {
		$password = "8sYWjtvMWgcVSq35GK9qrp4rqmdWd6vf"
	}
	$num = $nm::WriteToFile($passFile1, $password);
	
	& $openssl ecparam -name P-384 -genkey -param_enc named_curve -out $outKeyFile1 # secp384r1
	& $openSSL  req -x509 -key $outKeyFile1 -days 7300 -config $targetConfig -out $outFile -passout file:endpwd
	if (!$noPassword) {
		& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout file:endpwd
	}
	else {
		& $openSSL  pkcs12 -export -in $outFile -inkey $outKeyFile1 -CSP $csp -keyex -out $resultFile1 -passout pass:
	}
	& $openSSL  x509 -outform der -in $outFile -out $resultFile2
}
finally {
	Remove-Item $passFile1 -Force
	Remove-Item $configPath -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item $outputPath -Force -Recurse -ErrorAction SilentlyContinue
}
}
}
