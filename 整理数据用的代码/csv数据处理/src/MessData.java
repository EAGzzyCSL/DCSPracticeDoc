import java.io.*;
import java.util.ArrayList;
import java.util.StringJoiner;


abstract class MessData {
    private String dataType;
    private final String line = "------------------------------------------------------------";
    String hash = null;

    MessData(String dataType) {
        this.dataType = dataType;
    }

    private void writeToDisk(String s) {
        try {
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(dataType + ".json"));
            bufferedWriter.write(s);
            bufferedWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public abstract String deal(ArrayList<ArrayList<String>> blocks);

    private String deal(File file) {
        hash = file.getName().split("_")[0];
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
            ArrayList<String> allLine = new ArrayList<>();
            String tmp;
            // 读入全部
            while ((tmp = bufferedReader.readLine()) != null) {
                allLine.add(tmp);
            }
            ArrayList<ArrayList<String>> blocks = new ArrayList<>();
            for (int i = 0; i < allLine.size(); i++) {
                ArrayList<String> muLine = new ArrayList<>();
                while (!allLine.get(i).equals(line)) {
                    muLine.add(allLine.get(i));
                    i++;
                }
                blocks.add(muLine);
            }
            return deal(blocks);
        } catch (Exception e) {
            System.out.println("处理：‘" + file.getName() + "’失败");
            e.printStackTrace();
        }
        return null;
    }

    public void deal() {
        File folder = new File(dataType);
        File[] files = folder.listFiles();
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        if (files != null) {
            for (File file : files) {
                joiner.add(deal(file));
            }
        }
        writeToDisk(joiner.toString());
        System.out.println(dataType + ":done");
    }

    final void dealDebug() {
        File folder = new File(dataType);
        File[] files = folder.listFiles();
        if (files != null) {
            System.out.println(deal(files[0]));
        }
    }

    final String createJsonObjectFromObject(String key, String object) {
        StringJoiner joiner = new StringJoiner(":", "{", "}");
        joiner.add(
                createJsonString(key)
        ).add(
                object
        );
        return joiner.toString();
    }

    final String createJsonObjectFromObject(String[] arr) {
        StringJoiner joiner = new StringJoiner(",", "{", "}");
        for (String s : arr) {
            joiner.add(s);
        }
        return joiner.toString();
    }

    final String createJsonObjectFromObject(ArrayList<String> arr) {
        StringJoiner joiner = new StringJoiner(",", "{", "}");
        for (String s : arr) {
            joiner.add(s);
        }
        return joiner.toString();
    }

    final String createJsonObjectFromValue(String[] arr, String[] name) {
        StringJoiner joiner = new StringJoiner(",", "{", "}");
        if (name.length == arr.length) {
            for (int i = 0; i < arr.length; i++) {
                joiner.add(createJsonKeyValue(name[i], arr[i]));
            }
        } else {
            if (this instanceof OverView) {
                //专门针对overview里面filedetail的那个13的
                int i = 0;
                for (; i < 2; i++) {
                    joiner.add(createJsonKeyValue(name[i], arr[i]));
                }
                joiner.add(createJsonKeyValue(name[i], arr[i] + arr[i + 1]));
                i++;
                for (; i < name.length; i++) {
                    joiner.add(createJsonKeyValue(name[i], arr[i + 1]));
                }
            } else if (this instanceof NetWork) {
                int i = 0;
                for (; i < arr.length; i++) {
                    joiner.add(createJsonKeyValue(name[i], arr[i]));
                }
                for (; i < name.length; i++) {
                    joiner.add(createJsonKeyValue(name[i], ""));
                }
            }

        }

        return joiner.toString();
    }

    final String createJsonArrayFromObject(ArrayList<String> arr) {
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        for (String s : arr) {
            joiner.add(s);
        }
        return joiner.toString();

    }

    final String createJsonArrayFromObject(String[] arr) {
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        for (String s : arr) {
            joiner.add(s);
        }
        return joiner.toString();

    }

    final String createJsonArrayFromValue(String[] arr) {
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        for (String s : arr) {
            String tmp = createJsonString(s);
            if (!tmp.equals("\"\"")) {
                joiner.add(
                        tmp
                );
            }

        }
        return joiner.toString();
    }

    final String createJsonArrayFromValue(ArrayList<String> arr) {
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        for (String s : arr) {
            String tmp = createJsonString(s);
            if (!tmp.equals("\"\"")) {
                joiner.add(
                        tmp
                );
            }

        }
        return joiner.toString();
    }

    final String createJsonKeyValue(String key, String value) {
        return String.join(":",
                createJsonString(key),
                createJsonString(value)
        );
    }

    final String createJsonKeyObject(String key, String object) {
        return String.join(":",
                createJsonString(key),
                object
        );
    }

    /**
     * 给名称或值加引号
     *
     * @param s 需要加引号的字符串
     * @return 加了引号后的字符串
     */
    private String createJsonString(String s) {
        return String.join(s.replace("|", "").replace('"', '\''), "\"", "\"");
    }

    String joinMuLine(int start, ArrayList<String> muLine) {
        StringJoiner joiner = new StringJoiner("");
        for (int i = start; i < muLine.size(); i++) {
            joiner.add(muLine.get(i).trim());
        }
        return joiner.toString();

    }

    String joinMuLine(int start, ArrayList<String> muLine, String split) {
        StringJoiner joiner = new StringJoiner(split);
        for (int i = start; i < muLine.size(); i++) {
            String s = muLine.get(i).trim();
            if (!s.equals("")) {
                joiner.add(s);
            }
        }
        return joiner.toString();

    }

    void replaceEscape(ArrayList<String> muLine) {
        for (int i = 0; i < muLine.size(); i++) {
            muLine.set(i, muLine.get(i).replace("\\", "/"));
        }
    }
}
