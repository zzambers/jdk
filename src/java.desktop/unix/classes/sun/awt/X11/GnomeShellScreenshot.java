package sun.awt.X11;

import java.awt.Rectangle;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.io.File;
import javax.imageio.ImageIO;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.ImageReader;
import javax.imageio.ImageReadParam;
import java.awt.image.BufferedImage;
import java.util.Iterator;

import sun.awt.X11.XWM;

@SuppressWarnings("removal")
final class GnomeShellScreenshot {

    static final boolean sessionTypeWayland;
    static {
        sessionTypeWayland = AccessController.doPrivileged(
            new PrivilegedAction<Boolean>() {
                public Boolean run() {
                    return "wayland".equals(System.getenv("XDG_SESSION_TYPE"));
                }
            });
    }

    public static boolean isSessionWaylandGnomeShell() {
        return sessionTypeWayland && XWM.isMutter();
    }

    public static int[] getRGBPixels(final Rectangle bounds, final int[] pixelArray) {
        return AccessController.doPrivileged(
            new PrivilegedAction<int[]>() {
                @Override
                public int[] run() {
                    File tmpFile = null;
                    File imgFile = null;
                    ImageInputStream stream = null;
                    ImageReader reader = null;
                    BufferedImage img = null;
                    try {
                        tmpFile = File.createTempFile("java.awt.Robot",".png");
                        byte[] usedFilenameBytes = createScreenshotFile(tmpFile.getPath().getBytes());
                        if (usedFilenameBytes == null) {
                            return null;
                        }
                        imgFile = new File(new String(usedFilenameBytes));
                        stream = ImageIO.createImageInputStream(imgFile);
                        Iterator<ImageReader> iter = ImageIO.getImageReaders(stream);
                        if (!iter.hasNext()) {
                            return null;
                        }
                        reader = iter.next();
                        ImageReadParam param = reader.getDefaultReadParam();
                        /* only region we are interested in is read into memory */
                        param.setSourceRegion(bounds);
                        reader.setInput(stream, true, true);
                        img = reader.read(0, param);
                        return img.getRGB(0, 0, bounds.width, bounds.height, pixelArray, 0, bounds.width);
                    } catch (Exception e) {
                        return null;
                    } finally {
                        if (img != null) {
                            img.flush();
                        }
                        if (reader != null) {
                            reader.dispose();
                        }
                        if (stream != null) {
                            try {
                                stream.close();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        if (imgFile != null && imgFile.exists()) {
                            try {
                                imgFile.delete();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        if (tmpFile != null && !tmpFile.equals(imgFile) && tmpFile.exists()) {
                            try {
                                tmpFile.delete();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            });
    }

    private static synchronized native byte[] createScreenshotFile(byte[] filename);

}
