// CWE-89: SQL Injection
// An untrusted id flows through a helper into a concatenated executeQuery call.
// Expected detecting family: sast
import java.sql.Statement;

public class SqlInjection {
    void runQuery(Statement stmt, String id) throws Exception {
        // VULNERABLE SINK: query built by string concatenation
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public void getUser(Statement stmt, String id) throws Exception {
        runQuery(stmt, id); // id is untrusted
    }
}
