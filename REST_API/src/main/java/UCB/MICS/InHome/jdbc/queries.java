package UCB.MICS.InHome.jdbc;

public abstract class queries {
    public static String INSERT_DEVICE = "INSERT INTO devices (Name, Mac, dateAdded, Ipv4) VALUES (?, ?, ?, ?)";
    public static String UPDATE_REVISIONS = "INSERT INTO revisions (revisionDate) VALUES (?)";
    public static String DELETE_DEVICE = "DELETE FROM devices WHERE Mac = ?";
    public static String UPDATE_NAME = "UPDATE devices SET Name = ? WHERE Name = ?";
    public static String SELECT_ALL_DEVICES = "SELECT * FROM devices";
    public static String GET_ONE_DEVICE = "SELECT * FROM devices WHERE mac = ? LIMIT 1";
    public static String GET_ALL_POLICIES = "SELECT * FROM policies";
    public static String GET_POLICY_BY_DEVICE_FROM = "SELECT policyId FROM policies WHERE deviceFrom = ?";
    public static String GET_POLICY_BY_DEVICE_TO = "SELECT policyId FROM policies WHERE deviceTo = ?";
    public static String GET_POLICY_BY_DEVICE_ANY = "SELECT policyIg FROM policies WHERE deviceTo = ? OR deviceFrom = ?";
    public static String DELETE_POLICIES_BY_ID = "DELETE FROM policies WHERE policyId = ?";
}
