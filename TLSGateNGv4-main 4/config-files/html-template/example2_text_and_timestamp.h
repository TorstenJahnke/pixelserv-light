/* Example 2: Seite mit Text und Timestamp
 *
 * Zeigt eine HTML-Seite mit sichtbarem Text UND Timestamp.
 * Beispiel für AI-generierte Countermeasure-Seite.
 */

#ifndef INCLUDE_HTML_INDEX_H
#define INCLUDE_HTML_INDEX_H

/* HTML-Seite mit Text und Timestamp */
unsigned char index_html[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "    <meta charset=\"UTF-8\">\n"
    "    <title>Access Denied</title>\n"
    "    <style>\n"
    "        body {\n"
    "            font-family: Arial, sans-serif;\n"
    "            background-color: #f0f0f0;\n"
    "            margin: 50px;\n"
    "        }\n"
    "        .container {\n"
    "            background: white;\n"
    "            padding: 30px;\n"
    "            border-radius: 8px;\n"
    "            box-shadow: 0 2px 10px rgba(0,0,0,0.1);\n"
    "        }\n"
    "        h1 { color: #d32f2f; }\n"
    "        .timestamp { color: #666; font-size: 0.9em; }\n"
    "    </style>\n"
    "</head>\n"
    "<body>\n"
    "    <div class=\"container\">\n"
    "        <h1>Zugriff verweigert</h1>\n"
    "        <p>Diese Anfrage wurde aus Sicherheitsgründen blockiert.</p>\n"
    "        <p>Irgendwas und Text hier als Beispiel für AI-generierte Inhalte.</p>\n"
    "        <p class=\"timestamp\">Zeitpunkt der Blockierung: %s</p>\n"
    "    </div>\n"
    "</body>\n"
    "</html>";

unsigned int index_html_len = sizeof(index_html) - 1;

#endif /* INCLUDE_HTML_INDEX_H */
