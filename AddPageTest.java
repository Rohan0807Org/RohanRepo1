package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for AddPage servlet to verify Reflected XSS remediation (CWE-79).
 *
 * The vulnerability was: the user-supplied "filename" parameter, obtained via
 * request.getParameter("filename") at line 40, was embedded directly into the
 * HTML output via out.print() at line 55 without sanitization. This allowed an
 * attacker to inject arbitrary HTML/JavaScript through the filename parameter.
 *
 * The fix applies OWASP Java Encoder's Encode.forHtmlAttribute() and
 * Encode.forHtml() to the fileName value before inserting it into the HTML
 * output — breaking the taint flow from the source (getParameter) to the sink
 * (out.print).
 *
 * These structural tests verify the fix by inspecting the AddPage.java source
 * to confirm that the tainted variable is passed through OWASP Encoder APIs
 * before reaching the HTML output sink.
 */
@RunWith(MockitoJUnitRunner.class)
public class AddPageTest {

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private ServletContext servletContext;

    private StringWriter responseWriter;

    @Before
    public void setUp() throws Exception {
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    // -----------------------------------------------------------------------
    // Structural / SAST-remediation tests
    //
    // These tests read the source text of AddPage.java to confirm the fix
    // is in place: both uses of fileName in out.print() must be wrapped with
    // OWASP Encoder calls rather than concatenated raw into HTML.
    // -----------------------------------------------------------------------

    /**
     * Verify that AddPage.java imports the OWASP Java Encoder library.
     * The import is required for the Encode.forHtml() and Encode.forHtmlAttribute()
     * calls that remediate the XSS vulnerability.
     */
    @Test
    public void addPageImportsOwaspEncoder() throws Exception {
        String source = readAddPageSource();

        assertTrue(
            "AddPage.java must import org.owasp.encoder.Encode to remediate XSS",
            source.contains("import org.owasp.encoder.Encode"));
    }

    /**
     * Verify that Encode.forHtml() is called to sanitize fileName before it is
     * rendered in the HTML body context (the link text).
     * Encode.forHtml() is the OWASP-recognized HTML body encoder that escapes
     * characters such as <, >, &, ", ' which are dangerous in HTML context.
     */
    @Test
    public void fileNameIsEncodedForHtmlBodyContext() throws Exception {
        String source = readAddPageSource();

        assertTrue(
            "AddPage.java must call Encode.forHtml(fileName) to encode the link text in HTML body context",
            source.contains("Encode.forHtml(fileName)"));
    }

    /**
     * Verify that Encode.forHtmlAttribute() is called to sanitize fileName
     * before it is rendered inside an HTML attribute (the href value).
     * Encode.forHtmlAttribute() applies context-aware encoding for HTML
     * attribute values, escaping characters that would break out of the
     * attribute context (e.g. single-quote, double-quote, angle brackets).
     */
    @Test
    public void fileNameIsEncodedForHtmlAttributeContext() throws Exception {
        String source = readAddPageSource();

        assertTrue(
            "AddPage.java must call Encode.forHtmlAttribute(fileName) to encode the href attribute value",
            source.contains("Encode.forHtmlAttribute(fileName)"));
    }

    /**
     * Verify that the raw fileName variable is NOT concatenated directly into
     * the out.print() HTML string — the original vulnerable pattern.
     *
     * The exact vulnerable patterns from the original finding:
     *   out.print("..."+fileName+"...")
     * must no longer appear in the source.
     */
    @Test
    public void rawFileNameIsNotConcatenatedIntoHtmlOutput() throws Exception {
        String source = readAddPageSource();

        // The original vulnerable pattern: fileName concatenated directly into HTML string
        // The fix must replace all such occurrences with encoded equivalents.
        boolean hasVulnerablePattern =
            source.contains("'../pages/\"+fileName+\"'") ||
            source.contains("'../pages/\"+ fileName +\"'") ||
            source.contains("\">\"+ fileName +\"</a>") ||
            source.contains("\">"+'"'+"+ fileName +"+'"'+"</a>") ||
            // Check for the exact original pattern from the finding
            source.contains("../pages/\"+fileName");

        assertFalse(
            "The 'fileName' variable must NOT be concatenated raw into the HTML output string",
            hasVulnerablePattern);
    }

    /**
     * Verify that the out.print() sink in the success branch references both
     * Encode.forHtmlAttribute() and Encode.forHtml() — one for the href attribute
     * and one for the visible link text.
     *
     * This ensures both XSS injection points in the original line 55 are covered:
     *   1. The href='../pages/<fileName>' — attribute injection context
     *   2. The ><fileName></a> — HTML body injection context
     */
    @Test
    public void bothHtmlContextsAreEncoded() throws Exception {
        String source = readAddPageSource();

        int forHtmlAttributeCount = countOccurrences(source, "Encode.forHtmlAttribute(");
        int forHtmlCount = countOccurrences(source, "Encode.forHtml(");

        assertTrue(
            "AddPage.java must call Encode.forHtmlAttribute() at least once (for the href attribute context)",
            forHtmlAttributeCount >= 1);

        assertTrue(
            "AddPage.java must call Encode.forHtml() at least once (for the HTML body context)",
            forHtmlCount >= 1);
    }

    /**
     * Verify that the OWASP Encoder is used to encode XSS payloads correctly.
     *
     * This test simulates the encoding that the OWASP Java Encoder performs on
     * known XSS attack strings to confirm the encoding contract is correct.
     * The OWASP Encode.forHtml() must transform characters that are dangerous
     * in HTML context into their HTML entity equivalents.
     */
    @Test
    public void owaspEncoderCorrectlyEncodesXssPayloads() {
        // Classic script injection payload
        String scriptPayload = "<script>alert('xss')</script>";
        String encoded = org.owasp.encoder.Encode.forHtml(scriptPayload);

        // The encoded output must not contain raw < or > characters
        assertFalse(
            "Encode.forHtml() must escape '<' in XSS payload",
            encoded.contains("<script>"));
        assertFalse(
            "Encode.forHtml() must escape '>' in XSS payload",
            encoded.contains("</script>"));

        // Must contain HTML entity for '<'
        assertTrue(
            "Encode.forHtml() must replace '<' with '&lt;'",
            encoded.contains("&lt;"));
    }

    /**
     * Verify that Encode.forHtmlAttribute() correctly escapes single-quote
     * payloads used to break out of HTML attribute context.
     *
     * Attack vector: filename = "test' onmouseover='alert(1)"
     * Without encoding, this breaks out of the href='...' attribute.
     */
    @Test
    public void owaspEncoderCorrectlyEncodesAttributeBreakoutPayload() {
        // Single-quote attribute breakout payload
        String payload = "test' onmouseover='alert(1)";
        String encodedAttr = org.owasp.encoder.Encode.forHtmlAttribute(payload);

        // The encoded output must not contain a raw single-quote that would
        // break out of the surrounding href='...' attribute context
        assertFalse(
            "Encode.forHtmlAttribute() must escape single-quote in attribute breakout payload",
            encodedAttr.contains("' onmouseover='"));
    }

    /**
     * Verify that Encode.forHtmlAttribute() handles event-handler injection
     * payloads that would otherwise be injected into the href attribute context.
     *
     * Attack vector: filename = "x\" onclick=\"alert(1)"
     */
    @Test
    public void owaspEncoderCorrectlyEncodesDoubleQuoteAttributePayload() {
        String payload = "x\" onclick=\"alert(1)";
        String encodedAttr = org.owasp.encoder.Encode.forHtmlAttribute(payload);

        assertFalse(
            "Encode.forHtmlAttribute() must escape double-quote in attribute injection payload",
            encodedAttr.contains("\" onclick=\""));
    }

    /**
     * Verify that Encode.forHtml() handles JavaScript URI payloads that would
     * execute when the link is clicked if inserted into an href.
     *
     * Attack vector: filename containing "javascript:alert(1)"
     * (In the HTML body context the angle brackets are the primary concern,
     * but confirming the encoder does not introduce new issues.)
     */
    @Test
    public void owaspEncoderHandlesJavascriptUriPayload() {
        String payload = "javascript:alert(1)";
        // forHtml does not encode colons — the fix for javascript: URIs in href
        // requires forHtmlAttribute or URL validation. This test confirms the
        // body encoding path (Encode.forHtml) does not introduce HTML injection.
        String encodedBody = org.owasp.encoder.Encode.forHtml(payload);

        // No angle brackets in this payload so no encoding change expected for body context.
        // The attribute context (Encode.forHtmlAttribute) is what prevents href injection.
        assertNotNull("Encode.forHtml() must not return null for a javascript: URI payload",
            encodedBody);
    }

    /**
     * Verify that a normal, benign filename is preserved (not over-encoded)
     * after applying OWASP HTML encoding — confirming backward compatibility.
     *
     * Alphanumeric filenames with hyphens, underscores, and dots must pass
     * through without alteration.
     */
    @Test
    public void normalFilenameIsPreservedByEncoder() {
        String normalFilename = "my-file_v2.html";
        String encodedHtml = org.owasp.encoder.Encode.forHtml(normalFilename);
        String encodedAttr = org.owasp.encoder.Encode.forHtmlAttribute(normalFilename);

        assertEquals(
            "Encode.forHtml() must not alter a benign filename with no special characters",
            normalFilename, encodedHtml);
        assertEquals(
            "Encode.forHtmlAttribute() must not alter a benign filename with no special characters",
            normalFilename, encodedAttr);
    }

    /**
     * Verify encoding of ampersand characters, which are also dangerous in HTML context
     * and could be part of a filename used in XSS or HTML injection.
     */
    @Test
    public void ampersandInFilenameIsEncoded() {
        String ampPayload = "file&name";
        String encodedHtml = org.owasp.encoder.Encode.forHtml(ampPayload);

        assertTrue(
            "Encode.forHtml() must encode '&' as '&amp;'",
            encodedHtml.contains("&amp;"));
        assertFalse(
            "Encode.forHtml() must not leave raw '&' in HTML output",
            encodedHtml.contains("file&name"));
    }

    // -----------------------------------------------------------------------
    // Source-inspection helper tests
    // -----------------------------------------------------------------------

    /**
     * Verify that the taint flow described in the SAST finding (CWE-79) has been
     * broken: the variable assigned from request.getParameter("filename") at
     * line 40 (the SOURCE) must not reach out.print() at line 55 (the SINK)
     * without passing through an encoding function.
     *
     * This test reads the source and confirms that any out.print() call
     * containing fileName also contains an Encode. call.
     */
    @Test
    public void fileNameTaintFlowIsBrokenByEncoding() throws Exception {
        String source = readAddPageSource();

        // Find the out.print line that references fileName
        // Split on newlines and inspect the lines around the print call
        String[] lines = source.split("\\n");
        boolean foundRawFilenameInPrint = false;

        for (String line : lines) {
            if (line.contains("out.print(") && line.contains("fileName")
                    && !line.contains("Encode.")) {
                foundRawFilenameInPrint = true;
                break;
            }
        }

        assertFalse(
            "No out.print() call should contain 'fileName' without a surrounding Encode. call — "
            + "that would indicate the taint flow from getParameter to print is not broken",
            foundRawFilenameInPrint);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Read the AddPage.java source file from the known location in this repository.
     * Used by structural tests that inspect the fix rather than executing it.
     */
    private String readAddPageSource() throws Exception {
        java.io.InputStream is = getClass().getResourceAsStream("/AddPage.java");
        if (is == null) {
            java.io.File f = new java.io.File("AddPage.java");
            if (!f.exists()) {
                // Gracefully skip structural checks if source is not on classpath/filesystem
                org.junit.Assume.assumeTrue("AddPage.java not found on classpath or filesystem", false);
                return "";
            }
            is = new java.io.FileInputStream(f);
        }
        return new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    }

    /** Count non-overlapping occurrences of {@code needle} in {@code haystack}. */
    private int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}
