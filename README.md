# Petrik
Penandatangan elektronik dokumen pdf

## How to use
~~~~
String filename;
File filePdf;
File theKey; // crt file
String passphrase;
String posisi; // use kiriAtas, kiriBawah, kananAtas, kananBawah, invisible
Long randID;

Signer m = new Signer(filename, filePdf, theKey, passphrase, posisi);
m.setChatID(chatID);

Signer m = new Signer();
                                
m.setFileName(filename);
m.setFilePDF(filePdf);
m.setTheKey(theKey);
m.setPassphrase(passphrase);
m.setPosisi(posisi);
m.setRandomID(randID);								
m.setOcspServer("http://ocsp-url");
m.setTsaClientServer("http://tsa-client-url");
m.setTsaUser("TSA User");
m.setTsaPass("TSA Password");
Thread thread = new Thread(m);
RunnableFuture<Void> task = new FutureTask<>(thread, null);
task.run();
                                
try {
  task.get(); // menunggu task selesai dikerjakan
} catch (InterruptedException ex) {
  ex.printStackTrace();
} catch (ExecutionException ex) {
  ex.printStackTrace();
}
~~~~
