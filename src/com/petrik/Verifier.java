/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.petrik;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.SignaturePermissions;
import com.itextpdf.text.pdf.security.VerificationException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.util.Calendar;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Collection;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import sun.security.provider.certpath.OCSP;
import java.util.Iterator;
import java.util.Properties;

/**
 *
 * @author kleptococcus
 */
public class Verifier implements Runnable{
    private File filePDF;
    private String fileName;
    private String notification;
    public PdfPKCS7 pkcs7;
    private boolean integritas;
    KeyStore ks;
    private boolean verificationError = false;
    public String signerName;
    public String version;
    public String signatureAlgorithm;
    public String serialNumber;
    public String email;
    public String issuer;
    public String validFrom; 
    public String validTo; 
    private boolean[] keyUsage = new boolean[9];
    private boolean ocsp_cek;
    public List<String> extendedKeyUsage;
    public static String[] cerParam1 = new String[10];
    public String verifyResult = "";
  
    public void setFilePDF(File pdf){        
        this.filePDF = pdf;
    }
    
    public void setFileName(String name){        
        this.fileName = name;
    }
    
    public String getNotification() {
        return this.notification;
    }
    
    public void cekIntegritasData(AcroFields fields, String name) throws GeneralSecurityException
    {
      System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(name));
      System.out.println("Document revision: " + fields.getRevision(name) + " of " + fields.getTotalRevisions());
      Security.addProvider(new BouncyCastleProvider());
      pkcs7 = fields.verifySignature(name);
      System.out.println("Integrity check OK? " + pkcs7.verify());
      verifyResult += "Integrity : " + pkcs7.verify();
      integritas = pkcs7.verify();
    }
    
    public void showCertificateInfo(X509Certificate cert, Date signDate)
    {
      System.out.println("Issuer: " + cert.getIssuerDN());
      System.out.println("Subject: " + cert.getSubjectDN());

      SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
      validFrom = date_format.format(cert.getNotBefore());
      validTo = date_format.format(cert.getNotAfter());
      System.out.println("Valid from: " + date_format.format(cert.getNotBefore()));
      System.out.println("Valid to: " + date_format.format(cert.getNotAfter()));
      String tmp2 = "";
      try {
        cert.checkValidity(signDate);
        tmp2 = "The certificate was valid at the time of signing.";
        System.out.println(tmp2);
      } catch (CertificateExpiredException e) {
        tmp2 = "The certificate was expired at the time of signing.";
        System.out.println(tmp2);
      } catch (CertificateNotYetValidException e) {
        tmp2 = "The certificate wasn't valid yet at the time of signing.";
        System.out.println(tmp2);
      }
      
      verifyResult += "\n" + tmp2;
      String tmp = "";
      try {
        cert.checkValidity();
        tmp = "The certificate is still valid.";
        System.out.println(tmp);
      } catch (CertificateExpiredException e) {
        tmp = "The certificate has expired.";
        System.out.println(tmp);
      } catch (CertificateNotYetValidException e) {
        tmp = "The certificate isn't valid yet.";
        System.out.println(tmp);
      }
      
      verifyResult += "\n" + tmp;      
      verifyResult += "\nIssuer : " + cert.getIssuerDN();
    }
    
    public void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date) throws GeneralSecurityException, IOException {
        cekOCSP(signCert);
        if (ocsp.getCertStatus().toString().compareTo("GOOD") == 0) {
          ocsp_cek = true;
        } else if (ocsp.getCertStatus().toString().compareTo("UNKNOWN") == 0) {
          ocsp_cek = false;
        } else {
          ocsp_cek = false;
        }
    }
    
    
  
  OCSP.RevocationStatus ocsp = null;
    private boolean cekOCSP(X509Certificate cert) throws FileNotFoundException, CertificateException { 
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
//      X509Certificate CAcert = (X509Certificate)cf.generateCertificate(new FileInputStream("ca.cer"));
      ByteArrayInputStream in = new ByteArrayInputStream("-----BEGIN CERTIFICATE-----\nMIIDhTCCAm2gAwIBAgIIbSOluGHGf6gwDQYJKoZIhvcNAQELBQAwRTEXMBUGA1UE\nAwwOT1NEIExVIEtlbGFzIDIxHTAbBgNVBAoMFExlbWJhZ2EgU2FuZGkgTmVnYXJh\nMQswCQYDVQQGEwJJRDAeFw0xNjA4MTgwNTA1MzlaFw0yNjA4MTgwNTA1MzlaMEUx\nFzAVBgNVBAMMDk9TRCBMVSBLZWxhcyAyMR0wGwYDVQQKDBRMZW1iYWdhIFNhbmRp\nIE5lZ2FyYTELMAkGA1UEBhMCSUQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDXLoB1p2NBEM+4Uzs7D4RnSSFhw82AfWLS4A0tju6z6s4mbSWPuCYkp8OK\n/5LJFFphYBCpfCII3FxHcuKe4XEwTuuvW/tyzWql9j6YWWvmiiVLgodSVGJ0WeZs\nvMTnw9rDKt+b8q2rRnxD65FLeVpqU8AcD1MrM4lYh5cEJMtoEBKz99G5MC1pP7NW\nOnt1lQBwaqqqZs9th/mFEibzQYL+Y/qV0Qy/z5tlg8TwzyjP02d00ZLhQ2z7Zlnk\nARPPgQvCiscmkvtBEsEbYlw302Ex1geedmcS/zCnh/DMY4IVuz8ikIo0LJc+Qx+r\nHyQagTTt0gks0Z9Di5W+WOtOpVlTAgMBAAGjeTB3MB0GA1UdDgQWBBTeKM2LvGti\n+a5k6Zb+zhLkrulvzzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFN4ozYu8\na2L5rmTplv7OEuSu6W/PMBQGA1UdIAQNMAswCQYHYIJoAQIBATAOBgNVHQ8BAf8E\nBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAHg2HTn7u7WVGTiKIEQfUYpQW8p88rF6\n7bzgBv5vGqB/+agi00GR03/brxYm2lKf7JseMg8CY9ECa2Aq6f7IgFoJuJ6vOH7g\nDgej+3KTZ8IzHuEGXI1tQX6TopuqXgYClUCA57bnwk1krWSfPZmmQsqcOR1/lgyv\n96m+NDPNZ0uojEQqCQQQFwGD04KpNbmmgVIYFJ6chXYEsashUjF3dlBlit0jwb70\n8qOM9PwbxS8I6oV+oQky2bJ31AHgCV4PC0DRDuG+HYr3gOO/HqhCkGWfa2EcGryd\nDWhjipoYxmkI4TZi5A1gyAhNCx7hvaU0hl9gfVAiNMNc+8A+/OtCoQ4=\n-----END CERTIFICATE-----".getBytes());
      X509Certificate CAcert = (X509Certificate)cf.generateCertificate(in);
      
      try
      {
        ocsp = OCSP.check(cert, CAcert, URI.create("http://cvs-osd.lemsaneg.go.id/ocsp"), CAcert, new Date());
        System.out.println("CERT STATUS " + ocsp.getCertStatus().toString());
        return true;
      }
      catch (IOException ex) {
        System.out.println(ex);
        return false;
      }
      catch (CertPathValidatorException ex) {
        System.out.println(ex);
        System.out.println("Tidak ada koneksi internet");
      }
      return false;
    }
    
    public void cekSertifikat() throws GeneralSecurityException, IOException
    {
      Certificate[] certs = pkcs7.getSignCertificateChain();
      Calendar cal = pkcs7.getSignDate();

      List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);
      System.out.println("ERROR SIZE " + errors.size());
      if (errors.size() == 0) {
        verificationError = true;
      }
      else
      {
        verificationError = false;
      }
      for (int i = 1; i < certs.length; i++) {
        X509Certificate cert = (X509Certificate)certs[i];
        System.out.println("=== Certificate " + i + " ===");
        showCertificateInfo(cert, cal.getTime());
      }
      X509Certificate signCert = (X509Certificate)certs[0];
      X509Certificate issuerCert = certs.length > 1 ? (X509Certificate)certs[1] : null;
      System.out.println("=== Checking validity of the document at the time of signing ===");
      checkRevocation(pkcs7, signCert, issuerCert, cal.getTime());
      System.out.println("=== Checking validity of the document today ===");
      checkRevocation(pkcs7, signCert, issuerCert, new Date());
    }
    
    public void cekTandaTangan(AcroFields fields, String name, SignaturePermissions perms) throws GeneralSecurityException {
        
        List<AcroFields.FieldPosition> fps = fields.getFieldPositions(name);
    
          
          


        System.out.println("Digest algorithm: " + pkcs7.getHashAlgorithm());
        System.out.println("Encryption algorithm: " + pkcs7.getEncryptionAlgorithm());
        System.out.println("Filter subtype: " + pkcs7.getFilterSubtype());
        X509Certificate cert = pkcs7.getSigningCertificate();
        signerName = CertificateInfo.getSubjectFields(cert).getField("CN");
        email = CertificateInfo.getSubjectFields(cert).getField("E");
        issuer = CertificateInfo.getIssuerFields(cert).getField("CN");
        keyUsage = cert.getKeyUsage();
        extendedKeyUsage = cert.getExtendedKeyUsage();
        version = Integer.toString(cert.getVersion());
        signatureAlgorithm = cert.getSigAlgName();
        serialNumber = cert.getSerialNumber().toString();

        System.out.println("Name of the signer: " + CertificateInfo.getSubjectFields(cert).getField("CN"));
        System.out.println("Email: " + CertificateInfo.getSubjectFields(cert).getField("E"));
        System.out.println("Issuer: " + CertificateInfo.getIssuerFields(cert).getField("CN"));
        System.out.println("Tipe: " + cert.getType());
        
        verifyResult += "\nSigner : " + CertificateInfo.getSubjectFields(cert).getField("CN");
        //verifyResult += "\nIssuer : " + CertificateInfo.getIssuerFields(cert).getField("CN");


        if (pkcs7.getSignName() != null)
          System.out.println("Alternative name of the signer: " + pkcs7.getSignName());
        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
        System.out.println("Signed on: " + date_format.format(pkcs7.getSignDate().getTime()));
        
        verifyResult += "\nSigned on : " + date_format.format(pkcs7.getSignDate().getTime());
        if (pkcs7.getTimeStampDate() != null) {
          System.out.println("TimeStamp: " + date_format.format(pkcs7.getTimeStampDate().getTime()));
          TimeStampToken ts = pkcs7.getTimeStampToken();
          System.out.println("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
          System.out.println("Timestamp verified? " + pkcs7.verifyTimestampImprint());
        }
        System.out.println("Location: " + pkcs7.getLocation());
        System.out.println("Reason: " + pkcs7.getReason());
        PdfDictionary sigDict = fields.getSignatureDictionary(name);
        PdfString contact = sigDict.getAsString(PdfName.CONTACTINFO);
        if (contact != null)
          System.out.println("Contact info: " + contact);
        perms = new SignaturePermissions(sigDict, perms);
        System.out.println("Signature type: " + (perms.isCertification() ? "certification" : "approval"));
        System.out.println("Filling out fields allowed: " + perms.isFillInAllowed());
        System.out.println("Adding annotations allowed: " + perms.isAnnotationsAllowed());
        for (SignaturePermissions.FieldLock lock : perms.getFieldLocks()) {
          System.out.println("Lock: " + lock.toString());
        }
      
    }
    
    private String getCN(String name)
    {
      Properties prop = new Properties();
      String cn = null;
      try {
        prop.load(new StringReader(name.replaceAll(",", "\n")));
        prop.list(System.out);
        cn = (String)prop.get("CN");
      } catch (IOException ex) { 
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        }
      return cn;
    }
    
    private void cekTSA(PdfPKCS7 pkcs7) throws GeneralSecurityException {
        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");

        TimeStampToken ts = pkcs7.getTimeStampToken();





        Store certStore = ts.getCertificates();

        Collection certCollection = certStore.getMatches(ts.getSID());
        Iterator certIt = certCollection.iterator();
        X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

        X509Certificate tsaCer = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

        String cn = getCN(tsaCer.getSubjectDN().getName());
        String cn2 = getCN(tsaCer.getIssuerDN().getName());

        cerParam1[0] = cn.concat(",").concat(cn2);
        cerParam1[1] = Integer.toHexString(tsaCer.getVersion());
        cerParam1[2] = tsaCer.getSigAlgName();
        cerParam1[3] = tsaCer.getSubjectDN().toString();
        cerParam1[4] = tsaCer.getIssuerDN().toString();
        cerParam1[5] = tsaCer.getSerialNumber().toString();
        cerParam1[6] = tsaCer.getNotBefore().toString();
        cerParam1[7] = tsaCer.getNotAfter().toString();
        cerParam1[8] = tsaCer.getPublicKey().toString();
        System.out.println("cerParam1 = " + cerParam1[0]);
        System.out.println("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
        System.out.println("TimeStamp verified? " + pkcs7.verifyTimestampImprint());
      }
        
    public PdfPKCS7 veriSign(AcroFields fields, String name, SignaturePermissions perms) throws GeneralSecurityException, IOException { 
      System.out.println("---------------PROSES VALIDASI SERTIFIKAT---------------");
      cekIntegritasData(fields, name);

      System.out.println("\n\n\n---------------PROSES VALIDASI SERTIFIKAT---------------");
      cekSertifikat();

      System.out.println("\n\n\n---------------INSPECT SIGNATURE---------------");
      cekTandaTangan(fields, name, perms);

      System.out.println("\n\n\n---------------CEK TSA---------------");
      cekTSA(pkcs7);

      System.out.println(integritas);
      System.out.println(ocsp_cek);
      System.out.println(verificationError);
      return pkcs7;
    }
    
    public String toString(){
        return verifyResult;
    }
  
    public void doVerify() throws IOException, GeneralSecurityException
    {
        System.out.println(this.fileName + "\n");

//        try 
//        {
//            PdfReader reader = new PdfReader(resource);
            PdfReader reader = new PdfReader(filePDF.toString());
            AcroFields acroFields = reader.getAcroFields();

            ArrayList<String> names = acroFields.getSignatureNames();
            SignaturePermissions perms = null;
            for (String name : names) {
               System.out.println("Signature name: " + name);
//               System.out.println("Signature covers whole document: " + acroFields.signatureCoversWholeDocument(name));
//               System.out.println("Document revision: " + acroFields.getRevision(name) + " of " + acroFields.getTotalRevisions());
//               PdfPKCS7 pk = acroFields.verifySignature(name);
//               System.out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
//               System.out.println("Document verifies: " + pk.verify());
                veriSign(acroFields, name, perms);
            }
//        }

//        System.out.println();
    }
    
    @Override
    public void run() {
        try {
            doVerify();
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
