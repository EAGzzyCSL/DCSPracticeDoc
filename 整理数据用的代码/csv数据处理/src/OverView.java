import java.util.ArrayList;


class OverView extends MessData {
    private String[] AnalysisKey = {
            "Category", "Started", "Completed", "Duration"
    };
    private String[] fileDetailKey = {
            "File_Name", "File_Size", "File_Type",
            "fileTypeVer",
            "MD5", "SHA1", "SHA256", "SHA512", "CRC32",
            "Ssdeep", "Yara", "$dowload"
    };

    OverView(String dataType) {
        super(dataType);
    }

    @Override
    public String deal(ArrayList<ArrayList<String>> blocks) {
        return
                createJsonObjectFromObject(new String[]{
                        createJsonKeyValue("hash", hash),
                        dealAnalysis(blocks.get(1))
                        , dealFileDetail(blocks.get(2))
                        , dealSignatures(blocks.get(3))
                        , dealSummary_Files(blocks.get(6))
                        , dealSummary_Keys(blocks.get(7))
                        , dealSummary_Mutexes(blocks.get(8))
                });
    }

    private String dealAnalysis(ArrayList<String> muLine) {
        return createJsonKeyObject(
                "analysis",
                createJsonObjectFromValue(muLine.get(2).split(","), AnalysisKey)
        );
    }

    private String dealFileDetail(ArrayList<String> muLine) {
        return createJsonKeyObject(
                "FileDetail",
                createJsonObjectFromValue(
                        joinMuLine(2, muLine).split(","),
                        fileDetailKey)
        );
    }

    private String dealSignatures(ArrayList<String> muLine) {
        return createJsonKeyObject(
                "Signatures",
                createJsonArrayFromValue(
                        joinMuLine(1, muLine).split(",")
                )
        );
    }

    private String dealSummary_Files(ArrayList<String> muLine) {
        // 文件访问那路径的问题
        replaceEscape(muLine);
        return createJsonKeyObject(
                "Summary_Files",
                createJsonArrayFromValue(
                        joinMuLine(1, muLine, ",").split(",")
                )
        );
    }

    private String dealSummary_Keys(ArrayList<String> muLine) {
        replaceEscape(muLine);
        return createJsonKeyObject(
                "Summary_Keys",
                createJsonArrayFromValue(
                        joinMuLine(1, muLine, ",").split(",")
                )
        );
    }

    private String dealSummary_Mutexes(ArrayList<String> muLine) {
        replaceEscape(muLine);
        return createJsonKeyObject(
                "Summary_Mutexes",
                createJsonArrayFromValue(
                        joinMuLine(1, muLine, ",").split(",")
                )
        );
    }

}
