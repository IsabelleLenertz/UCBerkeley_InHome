package UCB.MICS.InHome.jdbc;

public abstract class queries {
    public static String INSERT_DEVICE = "INSERT INTO devices (Name, Mac, dateAdded, Ipv4) VALUES (?, ?, ?, ?)";
    public static String UPDATE_REVISIONS = "INSERT INTO revisions (revisionDate) VALUES (?)";
    public static String DELETE_DEVICE = "DELETE FROM devices WHERE Mac = ?";
    public static String UPDATE_NAME = "UPDATE devices SET Name = ? WHERE Name = ?";
    public static String SELECT_ALL_DEVICES = "SELECT * FROM devices";
    public static String GET_ONE_DEVICE = "SELECT * FROM devices WHERE mac = ? LIMIT 1";
    public static String GET_MAC_FROM_NAME = "SELECT Mac FROM devices WHERE Name = ? LIMIT 1";
    public static String GET_NAME_FROM_MAC = "SELECT * FROM devices WHERE Mac = ? or Mac = ?";
    public static String GET_NAME_FROM_ONE_MAC = "SELECT name FROM devices WHERE Mac = ?";
    public static String GET_ALL_POLICIES = "SELECT * FROM policies";
    public static String GET_POLICY_BY_DEVICE_ANY = "SELECT * FROM policies WHERE deviceTo = ? OR deviceFrom = ?";
    public static String DELETE_POLICY = "DELETE FROM policies WHERE deviceTo = ? OR deviceFrom = ?";
    public static String DELETE_BY_POLICY_ID = "DELETE FROM policies WHERE policyId = ?";
    public static String UPDATE_POLICIES = "INSERT INTO policies (deviceTo, deviceFrom) VALUES (?, ?)";
}
