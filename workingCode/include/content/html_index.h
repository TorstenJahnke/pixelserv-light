/*
To create this header file do this:
1. Erstelle die index.html mit allen Infos
2. Nutze xxd zum erstellen der header Datei:
   xxd -i index.html > html_index.h
3. Füge manuell '\0' am Ende hinzu (für String-Sicherheit)
4. Compilen
5. Info zu template Dateien:
   - BLANK_HTML.template > eine simple HTML Datei ohne irgendwelche Zusätze, wird als *.html immer genommen
   - ZERO_HTML.template > eine komplett leere HTML Datei mit 0 bytes

WICHTIG: index_html_len zählt NUR die HTML-Bytes, NICHT die Null-Terminierung!
         Das ermöglicht sowohl binäre Übertragung als auch sichere String-Operationen.
*/

#ifndef HTML_INDEX_H
#define HTML_INDEX_H

/* Null-terminiert für String-Sicherheit, aber index_html_len zählt nur Content */
unsigned char index_html[] = {'\0'};  /* Leerer String, null-terminiert */
unsigned int index_html_len = 0;      /* 0 Bytes Content */

#endif // HTML_INDEX_H

