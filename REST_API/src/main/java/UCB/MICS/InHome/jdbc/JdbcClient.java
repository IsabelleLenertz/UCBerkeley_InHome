package UCB.MICS.InHome.jdbc;

public class JdbcClient {
    private final String dbUrl;
    private final String dbUser;
    private final String dbPwd;

    public JdbcClient()
    {
        dbUrl = System.getenv("DB_URL");
        dbUser = System.getenv("DB_PORT");
        dbPwd = System.getenv("DB_PWD");
    }
}
