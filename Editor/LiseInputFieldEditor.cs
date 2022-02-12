using UnityEditor;
using UnityEditor.UI;


namespace LiSe.Auth
{

    [CustomEditor(typeof(LiSeInputField))]
    public class LiSeInputFieldEditor : InputFieldEditor
    {
        SerializedProperty m_uihandler;

        protected override void OnEnable()
        {
            base.OnEnable();
            m_uihandler = serializedObject.FindProperty("UIHandler");
        }

        public override void OnInspectorGUI()
        {
            base.OnInspectorGUI();
            EditorGUILayout.Space();

            serializedObject.Update();
            EditorGUILayout.PropertyField(m_uihandler);
            serializedObject.ApplyModifiedProperties();
        }
    }
}
