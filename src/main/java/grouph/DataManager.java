package grouph;

import java.io.File;

public class DataManager {
    public static String getDataPath(String fileName) {
        String os = System.getProperty("os.name").toLowerCase();
        String basePath;

        if (os.contains("win")) {
            String appData = System.getenv("APPDATA");
            basePath = appData != null ? appData : System.getProperty("user.home");
        } else if (os.contains("mac")) {
            basePath = System.getProperty("user.home") + "/Library/Application Support";
        } else {
            basePath = System.getProperty("user.home") + "/.local/share";
        }

        File dir = new File(basePath, "grouph");
        if (!dir.exists()) dir.mkdirs();

        return new File(dir, fileName).getAbsolutePath(); // return full path as String
    }
}
