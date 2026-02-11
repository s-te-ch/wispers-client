# JNA classes
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keep class * implements com.sun.jna.Callback { *; }
-keep class * extends com.sun.jna.Structure { *; }

# Keep our native library interface
-keep class dev.wispers.connect.internal.NativeLibrary { *; }
-keep class dev.wispers.connect.internal.NativeLibrary$* { *; }

# Keep callback interfaces (JNA needs these at runtime)
-keep class dev.wispers.connect.internal.NativeCallbacks { *; }
-keep class dev.wispers.connect.internal.NativeCallbacks$* { *; }

# Keep native types (JNA structure mappings)
-keep class dev.wispers.connect.internal.NativeTypes { *; }
-keep class dev.wispers.connect.internal.NativeTypes$* { *; }

# Keep storage callbacks (user-provided implementations)
-keep class dev.wispers.connect.storage.NodeStorageCallbacks { *; }
-keep class * implements dev.wispers.connect.storage.NodeStorageCallbacks { *; }
