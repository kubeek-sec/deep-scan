// CWE-89 (patched): PreparedStatement with a bound parameter.
// The taint engine must NOT flag this: prepareStatement gets a constant query
// and the untrusted value is bound via setString; executeQuery() takes no args.
import java.sql.Connection;
import java.sql.PreparedStatement;

public class SqlInjectionPatched {
    void runQuery(Connection conn, String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }

    public void getUser(Connection conn, String id) throws Exception {
        runQuery(conn, id);
    }
}
