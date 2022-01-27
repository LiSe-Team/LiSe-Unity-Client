using UnityEngine.UI;
using VrKeyboard;

namespace LiSe.Auth
{
    public class LiSeInputField : InputField
    {

        public UIHandler UIHandler;

        protected new void OnFocus() {
            if (UIHandler.UseVrKeyboard && UIHandler.VrKeyboard != null)
            {
                Keyboard kb = UIHandler.VrKeyboard.GetComponent<Keyboard>();
                if (kb != null)
                {
                    kb.OutputText = this;
                }
            }
        }
    }
}
