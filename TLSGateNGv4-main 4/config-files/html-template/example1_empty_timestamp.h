/* Example 1: Komplett leer mit Timestamp
 *
 * Zeigt nur den Timestamp, sonst nichts.
 * Minimale Response für Stealth-Blocking.
 */

#ifndef INCLUDE_HTML_INDEX_H
#define INCLUDE_HTML_INDEX_H

/* Nur Timestamp, keine HTML-Struktur */
unsigned char index_html[] = "%s";

unsigned int index_html_len = sizeof(index_html) - 1;

#endif /* INCLUDE_HTML_INDEX_H */
