// CWE-89 (patched): parameterized SqlCommand.
// The taint engine must NOT flag this: SqlCommand gets a constant query and the
// untrusted value is bound via Parameters.AddWithValue.
using System.Data.SqlClient;

class SqlInjectionPatched {
    void Run(SqlConnection conn, string name) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = @n", conn);
        cmd.Parameters.AddWithValue("@n", name);
        cmd.ExecuteReader();
    }

    public void Handle(SqlConnection conn, string name) {
        Run(conn, name);
    }
}
