using UnityEditor;

using UnityEngine;

namespace Fp.Utility.Cryptography.Editor
{
    public class Crc32GeneratorWindow : EditorWindow
    {
        [MenuItem("Tools/Utility/Crc32 Generator")]
        private static void ShowWindow()
        {
            var window = GetWindow<Crc32GeneratorWindow>();
            window.titleContent = new GUIContent("Crc32");
            window.Show();
        }

        private string _inputField;

        private uint _source;
        private uint _lower;
        private uint _upper;
        private Vector2 _scrollPosition;

        private void OnGUI()
        {
            float textLineHeight = GUI.skin.textArea.lineHeight;
            float editorWindowWidth = EditorGUIUtility.currentViewWidth;
            float textEditorWidth = editorWindowWidth - GUI.skin.verticalScrollbar.fixedWidth;
            
            float textHeight = GUIStyle.none.CalcHeight(new GUIContent(_inputField), textEditorWidth);
            float textAreaHeight = Mathf.Max(Mathf.Min(textLineHeight * 8, textHeight), textLineHeight);

            Rect scrollRect = GUILayoutUtility.GetRect(editorWindowWidth, textAreaHeight, GUIStyle.none);
            var textRect = new Rect(0, 0, textEditorWidth, textHeight);
            
            _scrollPosition = GUI.BeginScrollView(scrollRect, _scrollPosition, textRect);
            _inputField = GUI.TextArea(textRect, _inputField);
            
            var editor = (TextEditor)GUIUtility.GetStateObject(typeof(TextEditor), GUIUtility.keyboardControl);
            GUI.EndScrollView();

            bool autoScroll = GUI.changed || Event.current.keyCode == KeyCode.UpArrow || Event.current.keyCode == KeyCode.DownArrow;
            
            if (GUI.changed)
            {
                RecalculateCrc32();
            }

            if (autoScroll)
            {
                float textScrollHeight = (textHeight - textLineHeight);
                _scrollPosition.y = editor.graphicalCursorPos.y / textScrollHeight * (textHeight - textAreaHeight);
            }
            
            GUILayout.Label(editor.graphicalCursorPos.ToString());
            
            DrawHashResult(_source, "Source");
            DrawHashResult(_lower, "Source [LowerCase]");
            DrawHashResult(_upper, "Source [UpperCase]");
        }

        private void DrawHashResult(uint value, string label)
        {
            GUILayout.Label($"{label}:");
            GUILayout.Label($"Hash {value:X8} {value}");
            GUILayout.BeginHorizontal();
            if (GUILayout.Button($"Copy \"{value:X}\""))
            {
                EditorGUIUtility.systemCopyBuffer = value.ToString("X");
            }

            if (GUILayout.Button($"Copy \"{value:x8}\""))
            {
                EditorGUIUtility.systemCopyBuffer = value.ToString("X8");
            }

            if (GUILayout.Button($"Copy \"{value}\""))
            {
                EditorGUIUtility.systemCopyBuffer = value.ToString();
            }

            GUILayout.EndHorizontal();
        }

        private void RecalculateCrc32()
        {
            string lower = _inputField.ToLower();
            string upper = _inputField.ToUpper();
            
            _source = HashUtility.HashCrc32(_inputField);
            _lower = HashUtility.HashCrc32(lower);
            _upper = HashUtility.HashCrc32(upper);
        }
    }
}