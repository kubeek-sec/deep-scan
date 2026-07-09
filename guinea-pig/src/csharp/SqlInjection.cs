// CWE-89: SQL Injection
// An untrusted name flows through a helper into a concatenated SqlCommand.
// Expected detecting family: sast
using System.Data.SqlClient;

class SqlInjection {
    void Run(SqlConnection conn, string name) {
        // VULNERABLE SINK: query built by string concatenation
        var query = "SELECT * FROM users WHERE name = '" + name + "'";
        var cmd = new SqlCommand(query, conn);
        cmd.ExecuteReader();
    }

    public void Handle(SqlConnection conn, string name) {
        Run(conn, name); // name is untrusted
    }
}
