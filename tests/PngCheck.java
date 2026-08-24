// PngCheck.java — verify build/gradient.png is a valid PNG whose pixels exactly
// match the formula test_png.cpp used to generate it. Confirms the stb PNG
// encoder produces correct, standard-decodable output.
//
//   javac -d build cpp/PngCheck.java
//   java  -cp build PngCheck
import java.awt.image.BufferedImage;
import java.io.File;
import javax.imageio.ImageIO;

public class PngCheck {
    public static void main(String[] args) throws Exception {
        BufferedImage img = ImageIO.read(new File("build/gradient.png"));
        int W = 200, H = 120;
        if (img == null) { System.out.println("FAIL: could not decode PNG"); System.exit(1); }
        if (img.getWidth() != W || img.getHeight() != H) {
            System.out.println("FAIL: size " + img.getWidth() + "x" + img.getHeight());
            System.exit(1);
        }
        int mismatches = 0;
        for (int y = 0; y < H; y++) {
            for (int x = 0; x < W; x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF, g = (rgb >> 8) & 0xFF, b = rgb & 0xFF;
                int er = x & 0xFF, eg = y & 0xFF, eb = (x * 3 + y * 5) & 0xFF;
                if (r != er || g != eg || b != eb) mismatches++;
            }
        }
        if (mismatches == 0) System.out.println("PNG VALID: " + W + "x" + H + ", all " + (W * H) + " pixels exact");
        else System.out.println("FAIL: " + mismatches + " pixel mismatches");
        System.exit(mismatches == 0 ? 0 : 1);
    }
}
