package UCB.MICS.InHome.jdbc;

public abstract class queries {
    public static String INSERT_DEVICE = "INSERT INTO devices (Name, Mac, dateAdded, Ipv4) VALUES (?, ?, ?, ?)";
    public static String UPDATE_REVISIONS = "INSERT INTO revisions (revisionDate) VALUES (?)";

    public static String DELETE_DEVICE = "DELETE FROM devices WHERE Mac = ?";

}
