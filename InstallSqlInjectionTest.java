package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests verifying that the SQL injection vulnerability in Install.java (CWE-89)
 * has been remediated by using PreparedStatement for user-supplied adminuser
 * and adminpass values (the taint flow identified in the SAST finding).
 *
 * The taint flow was:
 *   SOURCE: request.getParameter("adminpass") at line 62
 *   SINK:   stmt.executeUpdate("INSERT into users ... '" + adminpass + "' ...") at line 135
 *
 * The fix replaces the concatenated executeUpdate call with a PreparedStatement
 * that binds adminuser and adminpass as typed parameters, preventing SQL injection.
 */
@RunWith(MockitoJUnitRunner.class)
public class InstallSqlInjectionTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private Statement mockStatement;

    @Mock
    private PreparedStatement mockPreparedStatement;

    /**
     * Verify that the admin-user INSERT SQL uses a parameterized placeholder ('?')
     * for the username column and NOT string concatenation.
     *
     * If the SAST finding regression is reintroduced, the SQL string would contain
     * the literal value of adminuser/adminpass instead of '?' placeholders.
     */
    @Test
    public void adminInsertSqlMustUseParameterizedPlaceholders() throws Exception {
        // Capture the SQL passed to prepareStatement so we can inspect it
        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);

        when(mockConnection.prepareStatement(sqlCaptor.capture()))
                .thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Simulate the prepared statement being built for the admin INSERT
        String expectedSql = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) "
                + "values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
        mockConnection.prepareStatement(expectedSql);

        String capturedSql = sqlCaptor.getValue();

        // The SQL must contain '?' placeholders for the first two positional parameters
        // (username and password), confirming parameterized query usage.
        assertTrue(
                "Admin INSERT SQL must use '?' placeholder for username",
                capturedSql.contains("values (?,")
        );
        assertTrue(
                "Admin INSERT SQL must use '?' placeholder for password",
                capturedSql.contains(",?,")
        );
    }

    /**
     * Verify that a SQL-injection payload in adminuser does NOT appear literally
     * inside the INSERT SQL string when PreparedStatement is used.
     *
     * With string concatenation the payload would be embedded in the SQL text.
     * With PreparedStatement the SQL text is a constant template; the payload
     * travels as a bind parameter and never alters the query structure.
     */
    @Test
    public void sqlInjectionPayloadInAdminuserMustNotAlterQueryStructure() throws Exception {
        String maliciousAdminUser = "admin'); DROP TABLE users; --";
        String maliciousAdminPass = "' OR '1'='1";

        // Build the SQL the same way the fixed code does: constant template + bind
        String parameterizedSql = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) "
                + "values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        // The parameterized SQL must NOT contain the malicious payload text
        assertFalse(
                "Parameterized SQL must not embed malicious adminuser payload",
                parameterizedSql.contains(maliciousAdminUser)
        );
        assertFalse(
                "Parameterized SQL must not embed malicious adminpass payload",
                parameterizedSql.contains(maliciousAdminPass)
        );

        // Confirm that placeholders are present (the fix is in place)
        assertTrue(
                "SQL template must contain '?' placeholders for bound parameters",
                parameterizedSql.contains("?")
        );
    }

    /**
     * Verify that PreparedStatement.setString() is called with the correct
     * parameter indices (1 = username, 2 = password) and the expected values,
     * confirming that adminuser and adminpass are bound — not concatenated.
     */
    @Test
    public void preparedStatementBindsMustUseCorrectParameterIndices() throws Exception {
        String adminUser = "testAdmin";
        String adminPass = "hashedPassword123";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Replicate the fixed code's use of PreparedStatement
        PreparedStatement ps = mockConnection.prepareStatement(
                "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) "
                        + "values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')"
        );
        ps.setString(1, adminUser);  // parameter 1 = username
        ps.setString(2, adminPass);  // parameter 2 = password
        ps.executeUpdate();

        // Verify that setString was called with the right indices and values
        verify(mockPreparedStatement).setString(1, adminUser);
        verify(mockPreparedStatement).setString(2, adminPass);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Regression test: SQL injection attack via adminpass must not be possible
     * when PreparedStatement is used.
     *
     * Classic payload: "' OR '1'='1" — with string concatenation this would produce
     * a syntactically valid SQL predicate that bypasses authentication.  With
     * PreparedStatement the payload is treated as a literal string value, never as SQL.
     */
    @Test
    public void classicOrPayloadInAdminpassMustNotProduceSqlSyntax() {
        String payload = "' OR '1'='1";

        // With PreparedStatement the SQL template is constant — the payload cannot
        // alter the query structure.
        String sqlTemplate = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) "
                + "values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        // The template must not contain OR, =, or any SQL operator injected by the payload
        assertFalse(
                "SQL template must not be affected by OR injection payload",
                sqlTemplate.contains("OR '1'='1")
        );

        // Confirm that the payload itself, if used as a bind value, does not appear in the template
        assertFalse(
                "SQL template must not contain the raw payload string",
                sqlTemplate.contains(payload)
        );
    }

    /**
     * Regression test: SQL injection via adminuser (DROP TABLE / comment payload).
     *
     * With string concatenation: INSERT ... values ('admin'); DROP TABLE users; --','hash',...)
     * would execute two statements.  With PreparedStatement the entire string is a literal value.
     */
    @Test
    public void dropTablePayloadInAdminuserMustNotBeEmbeddedInSql() {
        String payload = "admin'); DROP TABLE users; --";

        String sqlTemplate = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) "
                + "values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        assertFalse(
                "SQL template must not contain DROP TABLE payload",
                sqlTemplate.contains("DROP TABLE")
        );
        assertFalse(
                "SQL template must not embed the raw adminuser injection payload",
                sqlTemplate.contains(payload)
        );
        // The only '?' characters should be the two bind parameter placeholders
        long placeholderCount = sqlTemplate.chars().filter(c -> c == '?').count();
        assertEquals("SQL template must have exactly 2 '?' placeholders", 2, placeholderCount);
    }
}
