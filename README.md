Dit is de hello world example TA van OP-TEE die de attestation PTA oproept.
Het bevat recursieve oproepen van een functie om een bepaald aantal frames op de stapel te zetten. 
De functie gaat in oneindige lus zodat we zeker zijn dat tijdens het uitvoeren van de TA er een interrupt aankomt en attestatie wordt opgestart (bij attestatie op trigger van interrupts)

ta/sub.mk bevat een directive voor compilatie van ta met arm (niet thumb)

Installatie: deze bestanden slepen naar optee_examples/hello_world en elk bestand overwriten
