package com.petrik;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.provider.certpath.OCSP;

/**
 *
 * @author https://github.com/hermanka
 */
public class Signer implements Runnable{
    
    private File filePDF;
    private String passphrase;
    private File theKey;    
    private String posisi;
    private String fileName;
    private String tampilanTTD = "default";
    private Boolean truePass;
    private Boolean trueDoc;
    private String notification = null;
    private OCSP.RevocationStatus ocsp = null;
    private String ocspServer;
    private String tsaClientServer;
    private String tsaUser;
    private String tsaPass;    
    private String llx;
    private String lly;  
    private String urx;  
    private String ury;
    private PdfSignatureAppearance appearance;    
    private int height;
    private int width;
    private PdfReader reader;    
    private String pathSignedPDF;
    private Thread t;
    private String threadName;    
    private String randomID;
    
//    public Signer() throws FileNotFoundException{
//        this.filePDF = f;
//        this.passphrase = passphrase;
//        this.theKey = theKey;
//        this.posisi = posisiTTE;
//        this.fileName = fileName;       
//        
//        if(posisiTTE.equals("invisible")){
//            this.tampilanTTD = "invisible";
//        }
//    }
    
    public void setFileName(String name){        
        this.fileName = name;
    }
    
    public void setFilePDF(File pdf){        
        this.filePDF = pdf;
    }
    
    public void setTheKey(File key){        
        this.theKey = key;
    }
    
    public void setPassphrase(String pp){        
        this.passphrase = pp;
    }
    
    public void setPosisi(String pos){        
        this.posisi = pos;
        if(pos.equals("invisible")){
            this.tampilanTTD = "invisible";
        }
    }
        
    public String getNotification() {
        return this.notification;
    }
    
    public void setRandomID(Long id){
        this.randomID = Long.toString(id);
    }
    
    public void setOcspServer(String url){
        ocspServer = url;
    }
    
    public void setTsaClientServer(String url){
        tsaClientServer = url;
    }
    
    public void setTsaUser(String user){
        tsaUser = user;
    }
    public void setTsaPass(String pass){
        tsaPass = pass;
    }
    
    private  boolean cekKeyUsage(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage[0] == true) {
          return true;
        }
        return false;
    }
    
    private  boolean cekStatusSertifikat(X509Certificate cert) {
        try {
              cert.checkValidity();          
              notification = "Sertifikat valid";
              System.out.println(notification);
              return true;
        } catch (CertificateExpiredException e) {
              notification = "Sertifikat telah kadaluwarsa";
              System.out.println(notification);
              return false;
        } catch (CertificateNotYetValidException e) {
              notification = "Sertifikat tidak valid";
              System.out.println(notification);
              return false;
        }
    }
        
    private  boolean cekOCSP(X509Certificate cert) throws FileNotFoundException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // FileInputStream in = new FileInputStream("ca.crt");
        ByteArrayInputStream in = new ByteArrayInputStream("-----BEGIN CERTIFICATE-----\nMIIDhTCCAm2gAwIBAgIIbSOluGHGf6gwDQYJKoZIhvcNAQELBQAwRTEXMBUGA1UE\nAwwOT1NEIExVIEtlbGFzIDIxHTAbBgNVBAoMFExlbWJhZ2EgU2FuZGkgTmVnYXJh\nMQswCQYDVQQGEwJJRDAeFw0xNjA4MTgwNTA1MzlaFw0yNjA4MTgwNTA1MzlaMEUx\nFzAVBgNVBAMMDk9TRCBMVSBLZWxhcyAyMR0wGwYDVQQKDBRMZW1iYWdhIFNhbmRp\nIE5lZ2FyYTELMAkGA1UEBhMCSUQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDXLoB1p2NBEM+4Uzs7D4RnSSFhw82AfWLS4A0tju6z6s4mbSWPuCYkp8OK\n/5LJFFphYBCpfCII3FxHcuKe4XEwTuuvW/tyzWql9j6YWWvmiiVLgodSVGJ0WeZs\nvMTnw9rDKt+b8q2rRnxD65FLeVpqU8AcD1MrM4lYh5cEJMtoEBKz99G5MC1pP7NW\nOnt1lQBwaqqqZs9th/mFEibzQYL+Y/qV0Qy/z5tlg8TwzyjP02d00ZLhQ2z7Zlnk\nARPPgQvCiscmkvtBEsEbYlw302Ex1geedmcS/zCnh/DMY4IVuz8ikIo0LJc+Qx+r\nHyQagTTt0gks0Z9Di5W+WOtOpVlTAgMBAAGjeTB3MB0GA1UdDgQWBBTeKM2LvGti\n+a5k6Zb+zhLkrulvzzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFN4ozYu8\na2L5rmTplv7OEuSu6W/PMBQGA1UdIAQNMAswCQYHYIJoAQIBATAOBgNVHQ8BAf8E\nBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAHg2HTn7u7WVGTiKIEQfUYpQW8p88rF6\n7bzgBv5vGqB/+agi00GR03/brxYm2lKf7JseMg8CY9ECa2Aq6f7IgFoJuJ6vOH7g\nDgej+3KTZ8IzHuEGXI1tQX6TopuqXgYClUCA57bnwk1krWSfPZmmQsqcOR1/lgyv\n96m+NDPNZ0uojEQqCQQQFwGD04KpNbmmgVIYFJ6chXYEsashUjF3dlBlit0jwb70\n8qOM9PwbxS8I6oV+oQky2bJ31AHgCV4PC0DRDuG+HYr3gOO/HqhCkGWfa2EcGryd\nDWhjipoYxmkI4TZi5A1gyAhNCx7hvaU0hl9gfVAiNMNc+8A+/OtCoQ4=\n-----END CERTIFICATE-----".getBytes());
        X509Certificate CAcert = (X509Certificate)cf.generateCertificate(in);
        try {
            ocsp = OCSP.check(cert, CAcert, URI.create(ocspServer), CAcert, new Date());
            System.out.println("valid ocsp");
            return true;
        } catch (IOException ex) {
            notification = "Something happen, please try again later.";
            ex.printStackTrace();
            return false;
        } catch (CertPathValidatorException ex) {   
            notification = "Gagal menghubungi SignServer, cobalah beberapa saat lagi.";
            ex.printStackTrace();
            return false;
        }
    }
    
    private  String cekOutput(String dest) {
      int copyFile = 1;
      File file = new File(dest);
      String[] extension = dest.split(".pdf");
      dest = extension[0].concat("_" + randomID + "_sign.pdf");
      File target = new File(dest);
      while (target.exists()) {
        dest = extension[0].concat("_" + randomID + "_sign" + Integer.toString(copyFile) + ".pdf");
        target = new File(dest);
        copyFile++;
      }
      return target.getAbsolutePath();
    }
    
    public  void cekVisible() throws BadElementException, IOException, DocumentException {
      SecureRandom random = new SecureRandom();
      int i = random.nextInt();
      if (tampilanTTD.equals("default")) {
        cekPosisiTTD();
        appearance.setReason("Dokumen telah ditandatangani secara elektronik");
        appearance.setLocation("Jakarta");
        appearance.setVisibleSignature(new Rectangle(Float.parseFloat(llx), Float.parseFloat(lly), Float.parseFloat(urx), Float.parseFloat(ury)), 1, "sig" + Integer.toString(i));
    
      } else if (tampilanTTD.equals("invisible")) {
        appearance.setReason("Dokumen telah ditandatangani secara elektronik");
        appearance.setLocation("Jakarta");
      } else {
        cekPosisiTTD();
        appearance.setSignatureGraphic(Image.getInstance(tampilanTTD));
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
        appearance.setVisibleSignature(new Rectangle(Float.parseFloat(llx), Float.parseFloat(lly), Float.parseFloat(urx), Float.parseFloat(ury)), 1, "sig" + Integer.toString(i));
      }
    }
    
    private  void cekPosisiTTD() {
        height = ((int)reader.getPageSize(1).getHeight());
        width = ((int)reader.getPageSize(1).getWidth());
        if (posisi != null) {
            if (posisi.compareTo("kananAtas") == 0) {
              ury = Integer.toString(height);
              lly = Integer.toString(height - 48);
              urx = Integer.toString(width - 10);
              llx = Integer.toString(width - 150);
            } else if (posisi.compareTo("kananBawah") == 0) {
              ury = Integer.toString(48);
              lly = Integer.toString(0);
              urx = Integer.toString(width - 10);
              llx = Integer.toString(width - 150);
            } else if (posisi.compareTo("kiriAtas") == 0) {
              ury = Integer.toString(height);
              lly = Integer.toString(height - 48);
              urx = Integer.toString(170);
              llx = Integer.toString(30);
            } else if (posisi.compareTo("kiriBawah") == 0) {
              ury = Integer.toString(48);
              lly = Integer.toString(0);
              urx = Integer.toString(170);
              llx = Integer.toString(30);
            } else if (posisi.compareTo("kostumisasi") != 0) {}
        } else {
          ury = Integer.toString(height);
          lly = Integer.toString(height - 48);
          urx = Integer.toString(150);
          llx = Integer.toString(30);
        }
    }
        
    public  void sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm, String provider, MakeSignature.CryptoStandard subfilter, String reason, String location, Collection<CrlClient> crlList, OcspClient ocspClient, TSAClient tsaClient, int estimatedSize) throws GeneralSecurityException, IOException, DocumentException {
        try {
            TSAClient tsa = new TSAClientBouncyCastle(tsaClientServer, tsaUser, tsaPass);

            dest = cekOutput(fileName);
            this.pathSignedPDF = dest;
            reader = new PdfReader(src);
            FileOutputStream os = new FileOutputStream(dest);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\000', null, true);
            appearance = stamper.getSignatureAppearance();
            cekVisible();
            ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
            ExternalDigest digest = new BouncyCastleDigest();

            MakeSignature.signDetached(appearance, digest, pks, chain, crlList, ocspClient, tsa, estimatedSize, subfilter);
            
        
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    private void doSign() throws FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, CertPathValidatorException, GeneralSecurityException, IOException, DocumentException{
        try {            
            FileInputStream fis = new FileInputStream(theKey);
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            KeyStore keyStore = KeyStore.getInstance("pkcs12");        
            keyStore.load(fis, passphrase.toCharArray());        

            String alias = (String)keyStore.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, passphrase.toCharArray());
            Certificate[] certificateChain = keyStore.getCertificateChain(alias);
            truePass = true;
            trueDoc = true;        
            List<CrlClient> crlList = new ArrayList();
            crlList.add(new CrlClientOnline(certificateChain));
            OcspClient ocsp_ = new OcspClientBouncyCastle();

            if (cekKeyUsage((X509Certificate)certificateChain[0])) {
                if (cekStatusSertifikat((X509Certificate)certificateChain[0])) {
                  if (cekOCSP((X509Certificate)certificateChain[0]))
                  {
                      System.out.println(ocsp.getCertStatus().toString());
                    if (ocsp.getCertStatus().toString().compareTo("GOOD") == 0) {
                        sign(filePDF.toString(), filePDF.getName(), certificateChain, privateKey, "SHA-256", provider.getName(), MakeSignature.CryptoStandard.CMS, "Sign dengan CA_Cert", " Tampilan Default", crlList, ocsp_, null, 0);
                    }
                    if (ocsp.getCertStatus().toString().compareTo("UNKNOWN") == 0)
                    {
                        notification = "Sertifikat tidak dikenali.";
                        sign(filePDF.toString(), filePDF.getName(), certificateChain, privateKey, "SHA-256", provider.getName(), MakeSignature.CryptoStandard.CMS, "Sign tanpa CA_Cert", " Tampilan Default", crlList, null, null, 0);
                    }              
                  } 
                }
            }
        
        } catch (IOException ex) {
          notification = "Sertifikat dan Passphrase tidak sesuai";       
          truePass = false;
        } catch (NoSuchAlgorithmException ex) {
          ex.printStackTrace();
        } catch (CertificateException ex) {
          ex.printStackTrace();
        }        
    } 
          
    public String toString(){
        return this.pathSignedPDF;
    }
    
    @Override
    public void run() {
        try {
            doSign();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertPathValidatorException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (DocumentException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
