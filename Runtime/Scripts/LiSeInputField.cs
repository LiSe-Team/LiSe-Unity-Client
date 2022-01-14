using UnityEngine.UI;
using UnityEngine;
using VrKeyboard;

namespace LiSe.Auth
{
    public class LiSeInputField : InputField
    {

        public UIHandler UIHandler;

        private void Update()
        {
            if (isFocused)
            {
                if (UIHandler.UseVrKeyboard && UIHandler.VrKeyboard != null)
                {
                    Keyboard kb = UIHandler.VrKeyboard.GetComponent<Keyboard>();
                    if (kb != null)
                    {
                        kb.KeyPressed.RemoveAllListeners();
                        kb.EnterPressed.RemoveAllListeners();
                        kb.BackspacePressed.RemoveAllListeners();


                        kb.KeyPressed.AddListener(onKey);
                        kb.EnterPressed.AddListener(onEnter);
                        kb.BackspacePressed.AddListener(onBackspace);
                    }
                }
            }
        }

        protected void onKey(string s) {
            if (selectionAnchorPosition == selectionFocusPosition)
            {
                text = text.Insert(caretPosition, s);
                caretPosition += 1;
            } else
            {
                int start = Mathf.Min(selectionAnchorPosition, selectionFocusPosition);
                int end = Mathf.Max(selectionAnchorPosition, selectionFocusPosition);
                text = text.Remove(start, end - start).Insert(start, s);
            }
        }

        protected void onEnter() {
        }

        protected void onBackspace() {
            if (selectionAnchorPosition == selectionFocusPosition)
            {
                caretPosition -= 1;
                text = text.Remove(caretPosition, 1);
            }
            else
            {
                int start = Mathf.Min(selectionAnchorPosition, selectionFocusPosition);
                int end = Mathf.Max(selectionAnchorPosition, selectionFocusPosition);
                text = text.Remove(start, end - start);
                caretPosition = start;
            }

        }
    }
}
