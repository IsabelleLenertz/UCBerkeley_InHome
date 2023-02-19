package UCB.MICS.InHome.jdbc;

public abstract class queries {
    public static String INSERT_DEVICE = "INSERT INTO devices (Name, Mac, dateAdded, Ipv4) VALUES (?, ?, ?, ?)";
    public static String UPDATE_REVISIONS = "INSERT INTO revisions (revisionDate) VALUES (?)";
    public static String DELETE_DEVICE = "DELETE FROM devices WHERE Mac = ?";
    public static String UPDATE_NAME = "UPDATE devices SET Name = ? WHERE Name = ?";
    public static String SELECT_ALL_DEVICES = "SELECT * FROM devices";
    public static String GET_ONE_DEVICE = "SELECT * FROM devices WHERE mac = ? LIMIT 1";

}
