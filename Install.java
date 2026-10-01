    package org.cysecurity.cspf.jvl.controller;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.cysecurity.cspf.jvl.model.HashMe;

/**
 *
 * @author breakthesec
 */
public class Install extends HttpServlet {

    /**
     * Session attribute key used to store and verify the CSRF token for the
     * installation form.  The token is generated once per GET request and
     * must be submitted back (via a hidden form field) on every POST.
     * Checking the token against the session value (server-side state only
     * the legitimate user's browser can know) breaks the CSRF taint flow
     * reported by the SAST finding (CWE-352).
     */
    static final String CSRF_TOKEN_SESSION_ATTR = "install_csrf_token";

    /**
     * Cryptographically-secure random source for CSRF token generation.
     * SecureRandom is thread-safe and is reused across requests.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Allowlist of permitted JDBC driver class names.
     * Only these values may be passed to Class.forName() to prevent
     * unsafe reflection (CWE-470) via user-controlled input.
     */
    private static final Set<String> ALLOWED_JDBC_DRIVERS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "com.mysql.jdbc.Driver",
            "com.mysql.cj.jdbc.Driver",
            "org.postgresql.Driver",
            "oracle.jdbc.OracleDriver",
            "com.microsoft.sqlserver.jdbc.SQLServerDriver",
            "org.h2.Driver",
            "org.hsqldb.jdbcDriver",
            "org.sqlite.JDBC"
        ))
    );

    /**
     * Allowlist of permitted JDBC URL scheme prefixes (the portion after "jdbc:").
     * Only these sub-schemes are accepted to prevent Connection String Injection
     * (CWE-99) via a crafted "dburl" parameter.
     */
    private static final Set<String> ALLOWED_JDBC_SCHEMES = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "mysql",
            "postgresql",
            "oracle:thin",
            "sqlserver",
            "h2",
            "hsqldb",
            "sqlite"
        ))
    );

    /**
     * Validate a user-supplied JDBC base URL against an allowlist of permitted
     * schemes, enforce that no query parameters or extra properties have been
     * injected, and reconstruct a canonical URL from the parsed URI components.
     *
     * <p>A JDBC URL has the form {@code jdbc:<sub-scheme>://<host>[:<port>][/<path>]}.
     * We parse the part after the {@code jdbc:} prefix as a standard {@link URI}
     * so that the JDK's RFC-3986 parser—rather than custom regex—validates
     * structure and extracts the scheme, host, port, and path.  If the URI
     * parser accepts query or fragment components the URL is rejected because
     * those components are used to inject JDBC connection properties
     * (e.g. {@code ?allowLoadLocalInfile=true}).
     *
     * <p>Crucially, instead of returning the raw user-supplied string, this method
     * <em>reconstructs</em> the connection base-URL from the individually parsed and
     * validated URI components (scheme, host, port).  This breaks the taint flow
     * (CWE-99) because the value that eventually reaches
     * {@link java.sql.DriverManager#getConnection} is derived entirely from
     * the parsed, allowlist-checked fields, not from the raw request parameter.</p>
     *
     * @param url the value received from the HTTP request parameter "dburl"
     * @return a canonical, reconstructed JDBC base URL (e.g. {@code jdbc:mysql://host:port/})
     *         derived from the parsed URI components, not from the raw input string
     * @throws IllegalArgumentException if the URL is null, does not start with
     *         {@code jdbc:}, uses a disallowed sub-scheme, or contains injected
     *         query, fragment, or semicolon components
     */
    static String validateJdbcUrl(String url) {
        if (url == null) {
            throw new IllegalArgumentException("JDBC URL must not be null");
        }
        // JDBC URLs must begin with the "jdbc:" prefix
        if (!url.toLowerCase(java.util.Locale.ROOT).startsWith("jdbc:")) {
            throw new IllegalArgumentException("JDBC URL must start with 'jdbc:'");
        }
        // Extract the sub-scheme+authority portion (everything after "jdbc:")
        String afterJdbc = url.substring("jdbc:".length());

        // Reject semicolon-delimited property injection before URI parsing
        // (common in MS SQL Server URLs, e.g. "jdbc:sqlserver://host;prop=val").
        if (afterJdbc.contains(";")) {
            throw new IllegalArgumentException(
                "JDBC URL must not contain semicolons (;) to prevent connection property injection");
        }

        // Parse via java.net.URI to leverage the JDK's RFC-3986 parser.
        // For jdbc:oracle:thin-style URLs the sub-scheme contains a colon, so
        // we only parse the sub-scheme prefix up to the first colon to check
        // the allowlist, then parse the full host/authority part separately.
        URI parsedUri;
        try {
            parsedUri = new URI(afterJdbc);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Malformed JDBC URL: " + e.getMessage(), e);
        }

        // Reject URLs that carry query parameters – these are the primary
        // injection vector for JDBC connection string injection (CWE-99).
        if (parsedUri.getQuery() != null) {
            throw new IllegalArgumentException(
                "JDBC URL must not contain query parameters (?...) to prevent connection string injection");
        }
        // Reject fragment components as well
        if (parsedUri.getFragment() != null) {
            throw new IllegalArgumentException(
                "JDBC URL must not contain a fragment (#...) component");
        }

        // Validate the sub-scheme against the allowlist.
        // parsedUri.getScheme() returns the first component up to the first colon.
        String subScheme = parsedUri.getScheme();
        if (subScheme == null) {
            throw new IllegalArgumentException("JDBC URL is missing a sub-scheme after 'jdbc:'");
        }
        // Check simple sub-scheme; also check compound sub-schemes like "oracle:thin"
        boolean schemeAllowed = ALLOWED_JDBC_SCHEMES.contains(subScheme.toLowerCase(java.util.Locale.ROOT));
        if (!schemeAllowed) {
            for (String allowed : ALLOWED_JDBC_SCHEMES) {
                if (afterJdbc.toLowerCase(java.util.Locale.ROOT).startsWith(allowed + ":")) {
                    schemeAllowed = true;
                    break;
                }
            }
        }
        if (!schemeAllowed) {
            throw new IllegalArgumentException(
                "JDBC URL sub-scheme '" + subScheme + "' is not in the permitted allowlist");
        }

        // Reconstruct the base URL from parsed URI components rather than returning
        // the raw user-supplied string.  This breaks the taint flow: the value that
        // reaches DriverManager.getConnection() is built from individually validated
        // fields (allowlisted sub-scheme, RFC-3986-parsed host, numeric port), not
        // from the attacker-controlled input string.
        String host = parsedUri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("JDBC URL must specify a host");
        }
        int port = parsedUri.getPort(); // -1 if absent; DriverManager accepts that
        String canonicalSubScheme = subScheme.toLowerCase(java.util.Locale.ROOT);
        if (port > 0) {
            return "jdbc:" + canonicalSubScheme + "://" + host + ":" + port + "/";
        } else {
            return "jdbc:" + canonicalSubScheme + "://" + host + "/";
        }
    }

       static String dburl;
       static String jdbcdriver;
       static String dbuser;
       static String dbpass;
       static String dbname;
       static String siteTitle;
       static String adminuser;
       static String adminpass;
               
    /**
     * Generate a cryptographically-random, Base64-URL-encoded CSRF token,
     * store it in the user's session, and return it so it can be embedded
     * as a hidden field in the install form.
     *
     * <p>The token is 32 random bytes (256 bits), making brute-force
     * infeasible.  It is stored under {@link #CSRF_TOKEN_SESSION_ATTR} so
     * that {@link #processRequest} can compare the submitted value against
     * the session value using {@link String#equals}, which is sufficient
     * here because neither branch reveals timing information that helps an
     * attacker (the token is a random nonce, not a secret derived from
     * user credentials).</p>
     *
     * @param session the caller's HTTP session (must not be null)
     * @return the newly-generated token string
     */
    static String generateAndStoreCsrfToken(HttpSession session) {
        byte[] tokenBytes = new byte[32];
        SECURE_RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        session.setAttribute(CSRF_TOKEN_SESSION_ATTR, token);
        return token;
    }

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String configPath=getServletContext().getRealPath("/WEB-INF/config.properties");

        //Getting Database Configuration from User Input
        // Validate dburl via java.net.URI parsing + allowlist to prevent Connection
        // String Injection (CWE-99): reject query parameters, fragments, semicolons,
        // and disallowed JDBC sub-schemes before the value reaches DriverManager.
        String requestedDbUrl = request.getParameter("dburl");
        try {
            dburl = validateJdbcUrl(requestedDbUrl);
        } catch (IllegalArgumentException e) {
            response.setContentType("text/html;charset=UTF-8");
            try (PrintWriter out = response.getWriter()) {
                out.println("<!DOCTYPE html><html><body>Invalid database URL specified.</body></html>");
            }
            return;
        }
        // Validate jdbcdriver against an explicit allowlist before storing it.
        // Class.forName() is called with this value later; accepting arbitrary
        // class names from user input would allow unsafe reflection (CWE-470).
        String requestedDriver = request.getParameter("jdbcdriver");
        if (requestedDriver == null || !ALLOWED_JDBC_DRIVERS.contains(requestedDriver)) {
            response.setContentType("text/html;charset=UTF-8");
            try (PrintWriter out = response.getWriter()) {
                out.println("<!DOCTYPE html><html><body>Invalid JDBC driver specified.</body></html>");
            }
            return;
        }
        jdbcdriver = requestedDriver;
        dbuser = request.getParameter("dbuser");
        dbpass = request.getParameter("dbpass");
        dbname = request.getParameter("dbname");
        siteTitle= request.getParameter("siteTitle");
        adminuser= request.getParameter("adminuser");
        adminpass= HashMe.hashMe(request.getParameter("adminpass"));
        
        //Moifying Configuration Properties:
         Properties config=new Properties();
         config.load(new FileInputStream(configPath));
         config.setProperty("dburl",dburl);
         config.setProperty("jdbcdriver",jdbcdriver);
         config.setProperty("dbuser",dbuser);
         config.setProperty("dbpass",dbpass);
         config.setProperty("dbname",dbname);
         config.setProperty("siteTitle",siteTitle);
         FileOutputStream fileout = new FileOutputStream(configPath);
         config.store(fileout, null); 
         fileout.close();
         
        String i=request.getParameter("setup");
        response.setContentType("text/html;charset=UTF-8");
         try {
            PrintWriter out = response.getWriter();
            /* TODO output your page here. You may use following sample code. */
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet install</title>");            
            out.println("</head>");
            out.println("<body>");
            if(setup(i))
            {
                out.print("successfully installed");
            }
            else
            {
                out.print("Something went wrong. Unable to install");
            }
            out.println("</body>");
            out.println("</html>");
        }
         catch(Exception e)
         {
             
         }
    }
     protected boolean setup(String i) throws IOException
    {

       if(i.equals("1"))
       {

                    try
                   {
                    // Validate dbname as a safe SQL identifier (alphanumeric + underscore only,
                    // must start with a letter) to prevent SQL injection in DDL statements.
                    // PreparedStatement cannot parameterize database/schema identifiers in JDBC,
                    // so allowlist-based identifier validation is required before use in DDL.
                    if (dbname == null || !dbname.matches("[A-Za-z][A-Za-z0-9_]*")) {
                        return false;
                    }
                    Class.forName(jdbcdriver);
                    Connection con= DriverManager.getConnection(dburl,dbuser,dbpass);
                      if(con!=null && !con.isClosed())
                        {
                            //Database creation
                             Statement stmt = con.createStatement();
                             stmt.executeUpdate("DROP DATABASE IF EXISTS `" + dbname + "`");

                             stmt.executeUpdate("CREATE DATABASE `" + dbname + "`");
                             con.close();
                            con= DriverManager.getConnection(dburl+dbname,dbuser,dbpass);
                             stmt = con.createStatement();
                              if(!con.isClosed())
                            {
                                //User Table creation
                                stmt.executeUpdate("Create table users(ID int NOT NULL AUTO_INCREMENT, username varchar(30),email varchar(60), password varchar(60), about varchar(50),privilege varchar(20),avatar TEXT,secretquestion int,secret varchar(30),primary key (id))");
                                  PreparedStatement insertAdmin = con.prepareStatement("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')");
                                  insertAdmin.setString(1, adminuser);
                                  insertAdmin.setString(2, adminpass);
                                  insertAdmin.executeUpdate();
                                  insertAdmin.close();
                                  stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('victim','victim','victim@localhost','I am the victim of this application','default.jpg','user',1,'max')");
                                  stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('attacker','attacker','attacker@localhost','I am the attacker of this application','default.jpg','user',1,'bella')");
                                stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('NEO','trinity','neo@matrix','I am the NEO','default.jpg','user',1,'sentinel')");
                                stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('trinity','NEO','trinity@matrix','it is Trinity','default.jpg','user',1,'sentinel')");
                                 stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('Anderson','java','anderson@1999','I am computer programmer','default.jpg','user',1,'C++')");
                               
                                  //Posts table creation                                  
                                  stmt.executeUpdate("create table posts(postid int NOT NULL AUTO_INCREMENT, content TEXT,title varchar(100), user varchar(30), primary key (postid))");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Feel free to ask any questions about Java Vulnerable Lab','First Post', 'admin')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Hello Guys, this is victim','Second Post', 'victim')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Hello This is attacker','Third Post', 'attacker')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Trinity! Help!','Help','neo')");
                               
                               
                               stmt.executeUpdate("create table tdata(id int, page varchar(30))");
                               stmt.executeUpdate("Insert into tdata values(1,'ext1.html')");
                                stmt.executeUpdate("Insert into tdata values(2,'ext2.html')");
                                
                                //Messages Table Creation
                                stmt.executeUpdate("Create table Messages(msgid int NOT NULL AUTO_INCREMENT,name varchar(30),email varchar(60), msg varchar(500),primary key (msgid))");
                                stmt.executeUpdate("INSERT into Messages(name,email, msg) values ('TestUser','Test@localhost', 'Hi admin, how are you')");
                               
                                //User Messages Table Creation recipient, sender, email, msg
                                stmt.executeUpdate("Create table UserMessages(msgid int NOT NULL AUTO_INCREMENT,recipient varchar(30),sender varchar(30),subject varchar(60), msg varchar(500),primary key (msgid))");
                                 stmt.executeUpdate("INSERT into UserMessages(recipient, sender, subject, msg) values ('attacker','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
                                 stmt.executeUpdate("INSERT into UserMessages(recipient, sender, subject, msg) values ('victim','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
              
                                
                                 //Credit Card Table Creation
                                stmt.executeUpdate("Create table cards(id int,cardno varchar(80), cvv varchar(6),expirydate varchar(15))");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('1','4000123456789010','123','12/2014')");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('2','4111111111111111 ','321','7/2015')");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('3','5111111111111118','111','1/2017')");
                               
                                //Files List Table Creation
                                stmt.executeUpdate("Create table FilesList(fileid int NOT NULL AUTO_INCREMENT,path text,primary key (fileid))");
                                stmt.executeUpdate("INSERT into FilesList(path) values ('/docs/doc1.pdf')");
                                 stmt.executeUpdate("INSERT into FilesList(path) values ('/docs/exampledoc.pdf')");
                                
                                return true;
                            }
                              return false;
                        }
                   }
                   catch(SQLException ex)
                   {
                      System.out.println("SQLException: " + ex.getMessage());
                     System.out.println("SQLState: " + ex.getSQLState());
                     System.out.println("VendorError: " + ex.getErrorCode());
                   }
                   catch(ClassNotFoundException ex)
                   {
                       System.out.print("JDBC Driver Missing:<br/>"+ex);
                   }
      
       }
        return false;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * <p>GET requests are safe (read-only intent).  A fresh CSRF token is
     * generated, stored in the session, and forwarded to the install form
     * so the form can embed it as a hidden field.  No state-altering
     * operations are performed on GET.</p>
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Generate a fresh CSRF token for the install form on every GET.
        // The token is stored in the session; the form must submit it back.
        HttpSession session = request.getSession(true);
        generateAndStoreCsrfToken(session);
        // GET does not perform any state-altering operations — forward to the form.
        request.getRequestDispatcher("/install.jsp").forward(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * <p>CSRF protection (CWE-352): the submitted {@code _csrfToken} parameter
     * is validated against the token stored in the server-side session.  If the
     * values do not match (or are absent), the request is rejected with
     * HTTP 403 before any state-altering processing takes place.</p>
     *
     * <p>Cross-site requests forged by an attacker cannot carry the correct
     * token value because the Same-Origin Policy prevents the attacker's page
     * from reading the token from the user's session or from the install form
     * HTML.</p>
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // --- CSRF token validation (CWE-352 remediation) ---
        // Retrieve the token that was stored in the session when the form was served.
        HttpSession session = request.getSession(false);
        String sessionToken = (session != null)
                ? (String) session.getAttribute(CSRF_TOKEN_SESSION_ATTR)
                : null;
        // Retrieve the token submitted with the POST form body.
        String submittedToken = request.getParameter("_csrfToken");

        // Reject the request if either token is missing or they do not match.
        // String.equals() is used here because a CSRF token is a random nonce:
        // it does not derive from a secret value, so there is no timing-attack
        // surface to exploit.
        if (sessionToken == null || !sessionToken.equals(submittedToken)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "Invalid or missing CSRF token.");
            return;
        }

        // Invalidate the single-use token after validation to prevent replay.
        session.removeAttribute(CSRF_TOKEN_SESSION_ATTR);

        // Token is valid — proceed with state-altering installation.
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}