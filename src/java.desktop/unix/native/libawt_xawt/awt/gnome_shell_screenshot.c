#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <jvm_md.h>
#include <jni.h>

/* based on: glib-2.0/glib/gmacros.h */
#ifndef FALSE
#define FALSE   (0)
#endif

#ifndef TRUE
#define TRUE    (!FALSE)
#endif

/* based on: glib-2.0/glib/gtypes.h */
typedef char   gchar;
typedef int    gint;
typedef gint   gboolean;
typedef void*  gpointer;

/* based on: glib-2.0/gio/gioenums.h */
typedef enum
{
  G_BUS_TYPE_STARTER = -1,
  G_BUS_TYPE_NONE = 0,
  G_BUS_TYPE_SYSTEM  = 1,
  G_BUS_TYPE_SESSION = 2
} GBusType;

typedef enum
{
  G_DBUS_PROXY_FLAGS_NONE = 0,
  G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES = (1<<0),
  G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS = (1<<1),
  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START = (1<<2),
  G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES = (1<<3),
  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START_AT_CONSTRUCTION = (1<<4)
} GDBusProxyFlags;

typedef enum {
  G_DBUS_CALL_FLAGS_NONE = 0,
  G_DBUS_CALL_FLAGS_NO_AUTO_START = (1<<0),
  G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION = (1<<1)
} GDBusCallFlags;


/* based on: glib-2.0/gio/gdbusproxy.h */
typedef struct _GDBusProxy                    GDBusProxy;
typedef struct _GDBusInterfaceInfo            GDBusInterfaceInfo;
typedef struct _GCancellable                  GCancellable;

/* based on: glib-2.0/glib/gerror.h */
typedef struct _GError GError;

/* based on: glib-2.0/glib/gvariant.h */
typedef struct _GVariant        GVariant;

/* dummy we dont need to know members for these */
struct _GError;
struct _GDBusProxy;
struct _GDBusInterfaceInfo;
struct _GVariant;

/* based on: glib-2.0/gio/gdbusproxy.h */
typedef GDBusProxy *(*g_dbus_proxy_new_for_bus_sync_ptr)
(
    GBusType            bus_type,
    GDBusProxyFlags     flags,
    GDBusInterfaceInfo  *info,
    const gchar         *name,
    const gchar         *object_path,
    const gchar         *interface_name,
    GCancellable        *cancellable,
    GError              **error
);


typedef GVariant *(*g_dbus_proxy_call_sync_ptr)
(
    GDBusProxy          *proxy,
    const gchar         *method_name,
    GVariant            *parameters,
    GDBusCallFlags      flags,
    gint                timeout_msec,
    GCancellable        *cancellable,
    GError              **error
);

/* based on: glib-2.0/glib/gerror.h */
typedef void (*g_clear_error_ptr) (GError **err);

/* based on: glib-2.0/gobject/gobject.h */
typedef void (*g_object_unref_ptr) (gpointer object);

/* based on: glib-2.0/glib/gvariant.h */
typedef void (*g_variant_unref_ptr) (GVariant *value);
typedef GVariant *(*g_variant_new_ptr) (const gchar *format_string, ...);
typedef void (*g_variant_get_ptr) (GVariant *value, const gchar *format_string, ...);
/* based on: glib-2.0/glib/gmem.h */
typedef void (*g_free_ptr) (gpointer mem);

/* custom */
typedef enum  {
  INIT_REQUIRED = 0,
  OK = 1,
  ERROR = -1
} Status;


/* pointers to required libs/functions */
static void *libgio = NULL;
static void *libgobject = NULL;
static void *libglib = NULL;

/* libgio-2.0.so.0 */
static g_dbus_proxy_new_for_bus_sync_ptr   g_dbus_proxy_new_for_bus_sync = NULL;
static g_dbus_proxy_call_sync_ptr          g_dbus_proxy_call_sync = NULL;
/* libgobject-2.0.so.0 */
static g_object_unref_ptr                  g_object_unref = NULL;
/* libglib-2.0.so.0 */
static g_clear_error_ptr                   g_clear_error = NULL;
static g_variant_unref_ptr                 g_variant_unref = NULL;
static g_variant_new_ptr                   g_variant_new = NULL;
static g_variant_get_ptr                   g_variant_get = NULL;
static g_free_ptr                          g_free = NULL;

/* status of library loading */
static Status libsStatus = INIT_REQUIRED;


static int gnome_shell_screenshot_libs_dlopen(void)
{
    libgio = dlopen(JNI_LIB_NAME("gio-2.0"), RTLD_LAZY);
    if (libgio == NULL) {
        libgio = dlopen(VERSIONED_JNI_LIB_NAME("gio-2.0", "0"), RTLD_LAZY);
        if (libgio == NULL) {
            return -1;
        }
    }
    g_dbus_proxy_new_for_bus_sync = dlsym(libgio, "g_dbus_proxy_new_for_bus_sync");
    if (g_dbus_proxy_new_for_bus_sync == NULL) {
        return -1;
    }
    g_dbus_proxy_call_sync = dlsym(libgio, "g_dbus_proxy_call_sync");
    if (g_dbus_proxy_call_sync == NULL) {
        return -1;
    }

    libgobject = dlopen(JNI_LIB_NAME("gobject-2.0"), RTLD_LAZY);
    if (libgobject == NULL) {
        libgobject = dlopen(VERSIONED_JNI_LIB_NAME("gobject-2.0", "0"), RTLD_LAZY);
        if (libgobject == NULL) {
            return -1;
        }
    }
    g_object_unref = dlsym(libgobject, "g_object_unref");
    if (g_object_unref == NULL) {
        return -1;
    }

    libglib = dlopen(JNI_LIB_NAME("glib-2.0"), RTLD_LAZY);
    if (libglib == NULL) {
        libglib = dlopen(VERSIONED_JNI_LIB_NAME("glib-2.0", "0"), RTLD_LAZY);
        if (libglib == NULL) {
            return -1;
        }
    }
    g_clear_error = dlsym(libglib, "g_clear_error");
    if (g_clear_error == NULL) {
        return -1;
    }
    g_variant_unref = dlsym(libglib, "g_variant_unref");
    if (g_variant_unref == NULL) {
        return -1;
    }
    g_variant_new = dlsym(libglib, "g_variant_new");
    if (g_variant_new == NULL) {
        return -1;
    }
    g_variant_get = dlsym(libglib, "g_variant_get");
    if (g_variant_get == NULL) {
        return -1;
    }
    g_free = dlsym(libglib, "g_free");
    if (g_free == NULL) {
        return -1;
    }
    return 0;
}

static void gnome_shell_screenshot_libs_dlclose(void)
{
    if (libgio != NULL) {
        g_dbus_proxy_new_for_bus_sync = NULL;
        g_dbus_proxy_call_sync = NULL;
        dlclose(libgio);
    }
    if (libgobject != NULL) {
        g_object_unref = NULL;
        dlclose(libgobject);
    }
    if (libglib != NULL ) {
        g_clear_error = NULL;
        g_variant_unref = NULL;
        g_variant_new = NULL;
        g_variant_get = NULL;
        g_free = NULL;
        dlclose(libglib);
    }
}


static int gnome_shell_screenshot_libs_open(void)
{
    if (libsStatus != INIT_REQUIRED) {
        return libsStatus == OK ? 0 : -1;
    }
    if (gnome_shell_screenshot_libs_dlopen() != 0) {
        gnome_shell_screenshot_libs_dlclose();
        dlerror(); /* clear error */
        libsStatus = ERROR;
        return -1;
    }
    dlerror(); /* clear any possible error */
    libsStatus = OK;
    return 0;
}


static void gnome_shell_screenshot_dbus_proxy_close(GDBusProxy *proxy)
{
    if (proxy != NULL) {
        g_object_unref_ptr(proxy);
        proxy = NULL;
    }
}


static GDBusProxy *gnome_shell_screenshot_dbus_proxy_open(void)
{
    GDBusProxy *proxy = NULL;
    GError     *error = NULL;

    proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SESSION,
        G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
        NULL,
        "org.gnome.Shell.Screenshot",
        "/org/gnome/Shell/Screenshot",
        "org.gnome.Shell.Screenshot",
        NULL,
        &error);

    if (error) {
        g_clear_error(&error);
        error = NULL;
        if (proxy != NULL) {
            gnome_shell_screenshot_dbus_proxy_close(proxy);
            proxy = NULL;
        }
    }
    return proxy;
}


static gchar *gnome_shell_screenshot_dbus_proxy_screenshot(GDBusProxy *proxy, gchar *filename)
{
    GError *error = NULL;
    GVariant *retval = NULL;
    GVariant *args = NULL;
    const gchar *method = "Screenshot";
    gboolean success = 0;
    gchar *filenameUsed = NULL;

    /* args is floating reference (dealocation handeled by call) */
    args = g_variant_new(
        "(bbs)",
        FALSE /* show cursor */,
        FALSE /* flash */,
        filename);

    retval = g_dbus_proxy_call_sync(
        proxy, method, args, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error == NULL && retval != NULL) {
        g_variant_get(retval, "(bs)", &success, &filenameUsed);
    }
    if (filenameUsed != NULL && !success) {
        g_free(filenameUsed);
        filenameUsed = NULL;
    }
    if (error) {
        g_clear_error(&error);
        error = NULL;
    }
    if (retval != NULL) {
        g_variant_unref(retval);
        retval = NULL;
    }
    return filenameUsed;
}


static gchar *gnome_shell_screenshot_try_take(gchar *filename)
{
    GDBusProxy *proxy = NULL;
    gchar *filenameUsed = NULL;
    int ret = 0;

    ret = gnome_shell_screenshot_libs_open();
    if (ret != 0) {
        return NULL;
    }
    proxy = gnome_shell_screenshot_dbus_proxy_open();
    if (proxy == NULL) {
        return NULL;
    }
    filenameUsed = gnome_shell_screenshot_dbus_proxy_screenshot(proxy, filename);
    gnome_shell_screenshot_dbus_proxy_close(proxy);
    return filenameUsed;
}


static char *gnome_shell_screenshot_take(char *filename)
{
    char* filenameOut = NULL;
    gchar* filenameUsed = NULL;

    filenameUsed = gnome_shell_screenshot_try_take((gchar*)filename);
    if (filenameUsed == NULL) {
        return NULL;
    }
    filenameOut = calloc(1, strlen(filenameUsed) + 1);
    if (filenameOut != NULL) {
        strcpy (filenameOut, filenameUsed);
    }
    if (filenameUsed != NULL) {
        g_free(filenameUsed);
        filenameUsed = NULL;
    }
    return filenameOut;
}


static jbyteArray gnome_shell_screenshot_get_jbytearray(JNIEnv *env, char* str)
{
	jbyteArray retArray = NULL;
	size_t outLength = 0;
    if (str == NULL) {
        return NULL;
    }
    outLength = strlen(str);
    retArray = (*env)->NewByteArray(env, (jsize)outLength);
    if (retArray == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, retArray, 0, (jsize)outLength, (void*)str);
    return retArray;
}


JNIEXPORT jbyteArray JNICALL
Java_sun_awt_X11_GnomeShellScreenshot_createScreenshotFile(JNIEnv *env,
    jclass cls,
    jbyteArray filenameArray)
{
    char* filenameIn = NULL;
    char* filenameOut = NULL;
    jsize inLength = 0;
    jbyteArray retArray = NULL;

    inLength = (*env)->GetArrayLength(env, (jarray)filenameArray);
    filenameIn = calloc(1, (size_t)inLength + 1);
    if (filenameIn == NULL) {
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, filenameArray, 0, inLength, (void*)filenameIn);
    filenameIn[inLength] = '\0';
    filenameOut = gnome_shell_screenshot_take(filenameIn);
    if (filenameOut != NULL) {
        retArray = gnome_shell_screenshot_get_jbytearray(env, filenameOut);
        free(filenameOut);
    }
    if (filenameIn != NULL) {
        free(filenameIn);
    }
    return retArray;
}
